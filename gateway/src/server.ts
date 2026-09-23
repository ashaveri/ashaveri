import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { createHash, randomUUID } from 'node:crypto';
import {
  hashRequest,
  issueReceipt,
  randomNonce,
  sealDeploymentManifest,
  type Marking,
  type MarkingScheme,
  type ReceiptPayload,
  type SigningKey,
  type TeeKind,
} from '@ashaveri/receipt';
import type { AccessLog, AccessRecord } from './aclog.js';
import { AccessError, ReceiptNamespace, requireRouteScope, type CredentialStore } from './access.js';
import { fromBase64Url, toBase64Url } from './b64.js';
import { mockBackend, type BackendResponse, type CompletionBackend, type CompletionUsage } from './backend.js';
import { mockDeployment, type AttestationBundle, type Deployment } from './deployment.js';
import { fromHex, sha256, toHex } from './digest.js';
import { MarkedStreamTail, markBufferedBody, markingFrame, unmarked } from './marking.js';
import { parseChatCompletionRequest, RequestError } from './mock.js';
import { openMemoryReceiptStore, type ReceiptStore } from './store.js';

const NONCE_BYTES = 16;
// A cold model load can hold back the first streamed event for minutes.
const FIRST_EVENT_TIMEOUT_MS = 120_000;
const MAX_BUFFERED_BODY = 32 * 1024 * 1024;
/** Evidence is addressed by the digest it binds to, which is what its URL says. */
const REPORT_DATA_HEX = /^[0-9a-fA-F]{64}$/;

/** The scheme this gateway marks with when its operator asked for none, which is the shipped state. */
const DEFAULT_MARKING: MarkingScheme = 'none';

export interface GatewayOptions {
  readonly issuer?: string;
  readonly instance?: string;
  readonly key?: SigningKey;
  readonly deployment?: Deployment;
  readonly backend?: CompletionBackend;
  /**
   * Where issued receipts are kept, and for how long they stay fetchable. The default holds them
   * in this process, so they are gone when it stops; a deployment with a volume passes the file engine.
   */
  readonly store?: ReceiptStore;
  /**
   * The pipeline every route runs through. Required: there is no gateway without it,
   * and a default that admits everything would be a floor that opts out.
   */
  readonly access: CredentialStore;
  readonly accessLog: AccessLog;
  /**
   * Which marking scheme this gateway writes into a completion, from the registry published in
   * section 3.3 of `docs/receipt-spec.md`. `none`, the shipped default, adds no bytes to a customer's
   * response and signs a receipt that says so; `provenance-v1` writes the marking member into both
   * response shapes and signs its digest. Which of the two a deployment runs is the operator's
   * decision, and so is any duty a marking is meant to discharge.
   *
   * There is no spelling of this option that leaves the marking field out of a receipt. A v2 payload
   * always carries one, because an absent `mk` would read to a verifier as "unmarked" and as "this
   * build predates marking" at once, which is the silence the version exists to refuse.
   */
  readonly marking?: MarkingScheme;
}

export interface ManifestJson {
  readonly v: 1;
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
  readonly keys: readonly { kid: string; alg: 'Ed25519'; publicKey: string }[];
  readonly models: readonly { id: string; wts: string }[];
  readonly meas: { tee: TeeKind; m: string };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** A gateway this module built, which is the only instance that carries the registration tally. */
export type GatewayInstance = FastifyInstance & {
  /**
   * The route paths whose registration was checked against the scope table, sorted. A path this
   * list omits is a route that booted ungated, which is the one way to see that the hook was
   * registered after the routes it should have inspected.
   */
  scopeCheckedRoutes(): string[];
};

/**
 * A reply body is one line of whatever log the client keeps, and `JSON.stringify` is silent on U+2028 and
 * U+2029, so text that arrives standing as it was goes into a message as a second line. One site needs
 * this: a model name read out of a JSON body, which `JSON.parse` hands over unchanged. The request-chosen
 * text elsewhere is already held by something measured, not assumed. A socket carrying either separator in
 * a request line or a header name is refused 400 before a route runs, and a target quoted back by
 * admission therefore only ever holds the percent-encoded spelling; a credential id passes a character rule
 * on the way in and on the way out; and the parser packages escape these two where they build a message.
 * `asOneLine` in `packages/receipt/src/errors.ts` is the same rule for the same reason.
 */
function asOneLine(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, ' ');
}

function upstreamError(reply: { code: (n: number) => { send: (b: unknown) => unknown } }, message: string): void {
  reply.code(502).send({ error: { message, type: 'upstream_error' } });
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length);
  out.set(left);
  out.set(right, left.length);
  return out;
}

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message));
    }, ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

async function collect(response: BackendResponse): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of response.chunks) {
    size += chunk.byteLength;
    if (size > MAX_BUFFERED_BODY) {
      throw new Error('inference upstream response exceeded the buffering limit');
    }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, size);
}

export function buildGateway(options: GatewayOptions): GatewayInstance {
  const { access, accessLog } = options;
  const deployment =
    options.deployment ?? mockDeployment({ issuer: options.issuer, instance: options.instance, key: options.key });
  const backend = options.backend ?? mockBackend();
  const receipts = options.store ?? openMemoryReceiptStore();
  // Read once, where every other operator switch on this process is read: a completion is marked the
  // same way whichever route served it, and the value is reported on the start-up banner.
  const markingScheme = options.marking ?? DEFAULT_MARKING;
  // One HKDF over the deployment's own signing seed, for the whole process. The id a receipt is
  // fetched by is minted here rather than taken from the upstream, and nothing is written down to
  // make the fetch work: the id carries the tag of the credential that minted it.
  const receiptIds = new ReceiptNamespace(deployment.key);

  const app = Fastify({ bodyLimit: 16 * 1024 * 1024, logger: false });
  // The receipt binds the exact bytes the client sent, so the body is kept raw
  // instead of being parsed into a JS object first.
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_request, body, done) => {
    done(null, body);
  });

  // requireRouteScope is where the refusal lives, so no try/catch belongs here: an undeclared route
  // has to propagate out of register and stop the process, and re-throwing a caught error to achieve
  // that only hides which line stopped it.
  const checkedPaths = new Set<string>();
  app.addHook('onRoute', (routeOptions) => {
    const methods = Array.isArray(routeOptions.method) ? routeOptions.method : [routeOptions.method];
    for (const each of methods) {
      requireRouteScope(String(each), routeOptions.url);
    }
    // Counted after the lookups, so a route that stopped the boot is not also tallied as checked.
    // Fastify clones each GET into a HEAD of its own, so the tally is of paths and not of the
    // method-and-path pairs the loop above answers.
    checkedPaths.add(routeOptions.url);
  });

  interface RequestState {
    startedAt: number;
    rid: string;
    credential: string | null;
    /** The minting tag of the admitted credential, held so a route pays no derivation. */
    tag: string | null;
    auth: 'pop' | 'bearer' | null;
    scope: string | null;
    nonce: string | null;
    receiptId: string | null;
    deny: string | null;
    logged: boolean;
  }

  const states = new WeakMap<FastifyRequest, RequestState>();

  function stateOf(request: FastifyRequest): RequestState | undefined {
    return states.get(request);
  }

  async function flush(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const state = stateOf(request);
    if (state === undefined || state.logged) return;
    // Set before the write, so a log that rejects this record costs the request its only line: the
    // alternative is a retry that can land a second line for one request once both listeners fire.
    state.logged = true;
    const record: AccessRecord = {
      t: state.startedAt,
      rid: state.rid,
      cred: state.credential,
      auth: state.auth,
      scope: state.scope,
      m: request.method,
      p: request.url.split('?', 1)[0] ?? request.url,
      rcp: state.receiptId,
      nce: state.nonce,
      st: reply.statusCode,
      dur: Date.now() - state.startedAt,
      deny: state.deny,
    };
    // A log that cannot take a line is an incident, not a reason to fail a request the pipeline
    // already decided. The rejection stops here so it cannot become an unhandled one.
    try {
      await accessLog.record(record);
    } catch (err) {
      request.log.warn({ err }, 'the access log refused a record');
    }
  }

  app.addHook('onRequest', async (request, reply) => {
    states.set(request, {
      startedAt: Date.now(),
      rid: randomUUID(),
      credential: null,
      tag: null,
      auth: null,
      scope: null,
      nonce: null,
      receiptId: null,
      deny: null,
      logged: false,
    });
    // finish and close, both, because a hijacked streaming reply ends on close and a
    // buffered one on finish, and a record this process loses is a gap nobody can
    // account for later. The logged flag makes the pair idempotent.
    reply.raw.once('finish', () => {
      void flush(request, reply);
    });
    reply.raw.once('close', () => {
      void flush(request, reply);
    });
  });

  app.addHook('preHandler', async (request, reply) => {
    const state = stateOf(request);
    if (state === undefined) return;
    // Before any admission: a store opened on a path serves decisions from the file it
    // loaded at boot until this reloads it, and a bearer request must see a fresh file too.
    await access.reloadIfNeeded();
    try {
      const admitted = access.admit({
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: request.body instanceof Buffer ? new Uint8Array(request.body.buffer, request.body.byteOffset, request.body.byteLength) : null,
        // The socket's own peer, and not `request.ip`: Fastify documents that value as derived from the
        // forwarding headers once an operator turns `trustProxy` on for some other reason, and a throttle
        // keyed on a header the caller writes is one the caller can point at somebody else's address or
        // reset on every request. So no header supplies an address here, in either spelling. The cost is
        // honest and stated in `docs/access-control.md`: behind a reverse proxy every peer address is the
        // proxy's, and this is not a per-client limit unless an operator puts a trusted proxy in front
        // and has it pass the real address on. Doing that takes a deliberate trust decision at this line,
        // which is where anyone reaching for `X-Forwarded-For` will find this paragraph.
        peerAddress: request.socket.remoteAddress,
      });
      state.credential = admitted.credentialId;
      // Held on the request the moment admission names the credential, so a mint and a read compare
      // the same value they were admitted with rather than looking one up again per request.
      state.tag = receiptIds.tagFor(admitted.credentialId);
      state.auth = admitted.auth;
      state.scope = admitted.scope;
      state.nonce = admitted.nonce === null ? null : toBase64Url(admitted.nonce);
      state.receiptId = admitted.receiptId;
    } catch (err) {
      if (!(err instanceof AccessError)) throw err;
      // What this gateway decided, not what the caller was told. The two differ where a refusal is
      // collapsed and where one answer covers two limits: the reason belongs to the deployer, and the
      // answer stays uniform on purpose. This is the only place a refusal's code reaches a caller, and
      // nothing in the types stops `logCode` being sent instead, so this line's `err.code` is held by
      // `test/peer-throttle.test.ts` and the route matrix rather than by the compiler.
      state.deny = err.logCode;
      if (state.credential === null) state.credential = err.credentialId ?? null;
      if (err.retryAfterSeconds !== undefined) reply.header('retry-after', String(err.retryAfterSeconds));
      await reply.code(err.status).send({ error: { message: err.message, type: 'authentication_error', code: err.code } });
      return;
    }
  });

  const manifest: ManifestJson = {
    v: 1,
    iss: deployment.issuer,
    ins: deployment.instance,
    epk: deployment.epk,
    keys: [{ kid: toHex(deployment.key.kid), alg: 'Ed25519', publicKey: toBase64Url(deployment.key.publicKey) }],
    models: deployment.models.map((model) => ({ id: model.id, wts: toHex(model.wts) })),
    meas: { tee: deployment.tee, m: toHex(deployment.measurement) },
  };

  async function issue(args: {
    id: string;
    nonce: Uint8Array;
    requestBody: Buffer;
    responseHash: Uint8Array;
    modelId: string;
    weights: Uint8Array;
    evidence: AttestationBundle;
    usage: CompletionUsage;
    marking: Marking;
  }): Promise<void> {
    const iat = Math.floor(Date.now() / 1000);
    // A v2 payload, always, whatever the marking says. `mk` is a required member of it, so the
    // answer to "was this response marked?" is a value in a signed document rather than the absence
    // of one, which is the reading a v1 receipt cannot carry and section 6 of the specification says
    // is why the version moved.
    const payload: ReceiptPayload = {
      v: 2,
      iss: deployment.issuer,
      ins: deployment.instance,
      iat,
      nce: args.nonce,
      req: hashRequest(args.requestBody),
      res: args.responseHash,
      mdl: args.modelId,
      wts: args.weights,
      meas: { tee: deployment.tee, m: deployment.measurement },
      att: { d: sha256(args.evidence.document), ts: args.evidence.timestamp, url: args.evidence.url },
      epk: deployment.epk,
      tok: { p: args.usage.promptTokens, c: args.usage.completionTokens },
      mk: args.marking,
    };
    // How long this stays fetchable is the store's decision, so the gateway hands over the
    // timestamp the decision is made from rather than making it here.
    await receipts.put(args.id, issueReceipt(payload, deployment.key), iat);
  }

  // The document, in whichever of the two shapes this deployment is able to produce.
  //
  // Sealing is not a mode a process can guess its way into: it happens when an operator handed this
  // deployment a key for the purpose, and the bytes served are then a COSE_Sign1 around exactly the
  // JSON written below, so what a client verifies is what it reads rather than a rendering of it. With
  // no such key the route serves the plain document it always did, which is not a failure and is not
  // secret: an unsigned manifest is the state a real deployment can be in, and a client that cannot
  // authenticate one says so out loud instead of quietly believing it.
  //
  // Turning this on is a compatibility event and the operator's decision: a client that predates sealed
  // manifests reads the CBOR as a manifest that will not parse and refuses the deployment rather than
  // misreading it, which is the same contract a receipt version the reader does not know already holds.
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const sealedManifest =
    deployment.manifestKey === undefined ? null : sealDeploymentManifest(manifestBytes, deployment.manifestKey);

  app.get('/v1/deployment-manifest', async (_request, reply) => {
    if (sealedManifest === null) return manifest;
    reply.header('content-type', 'application/cose');
    reply.send(Buffer.from(sealedManifest));
  });

  app.get('/v1/attestation', async (request, reply) => {
    const query = request.query as { report_data?: string };
    let reportData: Uint8Array | null = null;
    if (query.report_data !== undefined) {
      if (!REPORT_DATA_HEX.test(query.report_data)) {
        reply
          .code(400)
          .send({ error: { message: 'report_data must be 64 hex characters', type: 'invalid_request_error' } });
        return;
      }
      reportData = fromHex(query.report_data);
    }
    const bundle = await deployment.attestation(reportData);
    reply.header('content-type', 'application/octet-stream');
    reply.send(Buffer.from(bundle.document));
  });

  // The device leg has no standing answer to fall back on: an accelerator document is
  // only worth fetching if it names the challenge of the receipt being checked.
  app.get('/v1/attestation/gpu', async (request, reply) => {
    if (deployment.deviceAttestation === undefined) {
      reply.code(404).send({ error: { message: 'this deployment makes no device claim', type: 'not_found' } });
      return;
    }
    const query = request.query as { report_data?: string };
    if (query.report_data === undefined || !REPORT_DATA_HEX.test(query.report_data)) {
      reply.code(400).send({
        error: { message: 'report_data must be 64 hex characters', type: 'invalid_request_error' },
      });
      return;
    }
    const device = await deployment.deviceAttestation(fromHex(query.report_data));
    reply.header('content-type', 'application/octet-stream');
    reply.send(Buffer.from(device.document));
  });

  app.get('/v1/receipts/:id', async (request, reply) => {
    const id = (request.params as { id: string }).id;
    // The tag is checked before the store is asked, and a mismatch is answered exactly as an absent
    // record is: this route discloses nothing about whether the bytes exist for another tenant. The
    // id this caller presented still goes into the message, unchanged, because a refusal that quotes
    // a different text would itself be a signal.
    const tag = stateOf(request)?.tag;
    const bytes = typeof tag !== 'string' || !receiptIds.carries(id, tag) ? null : await receipts.get(id);
    if (bytes === null) {
      reply.code(404).send({ error: { message: `no receipt for id ${id}`, type: 'not_found' } });
      return;
    }
    reply.header('content-type', 'application/cbor');
    reply.send(Buffer.from(bytes));
  });

  app.post('/v1/chat/completions', async (request, reply) => {
    if (!(request.body instanceof Buffer)) {
      reply.code(400).send({ error: { message: 'request body must be application/json', type: 'invalid_request_error' } });
      return;
    }
    const raw = request.body;
    let parsed;
    try {
      parsed = parseChatCompletionRequest(JSON.parse(raw.toString('utf8')));
    } catch (err) {
      const message = err instanceof RequestError ? err.message : 'request body is not valid JSON';
      reply.code(400).send({ error: { message, type: 'invalid_request_error' } });
      return;
    }
    const declared = deployment.models.find((model) => model.id === parsed.model);
    if (declared === undefined) {
      reply.code(400).send({
        error: { message: asOneLine(`model '${parsed.model}' is not served by this deployment`), type: 'invalid_request_error' },
      });
      return;
    }
    let nonce: Uint8Array;
    const rawNonceHeader = request.headers['x-ashaveri-nonce'];
    const nonceHeader = Array.isArray(rawNonceHeader) ? rawNonceHeader[0] : rawNonceHeader;
    if (nonceHeader !== undefined) {
      try {
        nonce = fromBase64Url(nonceHeader);
      } catch {
        reply.code(400).send({ error: { message: 'x-ashaveri-nonce is not valid base64url', type: 'invalid_request_error' } });
        return;
      }
      if (nonce.length !== NONCE_BYTES) {
        reply.code(400).send({ error: { message: `x-ashaveri-nonce must be ${NONCE_BYTES} bytes`, type: 'invalid_request_error' } });
        return;
      }
    } else {
      nonce = randomNonce();
    }

    // The id each arm below mints is this credential's tag plus fresh randomness. Read once, before
    // the upstream is called: a completion whose receipt cannot be addressed is not worth an
    // inference call, and a mint without a tag would be addressed by a prefix no credential computes,
    // so its receipt would be unreadable by everyone including its owner.
    const receiptTag = stateOf(request)?.tag;
    if (typeof receiptTag !== 'string') {
      reply.code(500).send({
        error: {
          message: 'this request was admitted without a credential, so its receipt could not be addressed',
          type: 'server_error',
        },
      });
      return;
    }

    let response: BackendResponse;
    try {
      response = await backend.respond(raw, parsed);
    } catch (err) {
      upstreamError(reply, `inference upstream failed: ${errorMessage(err)}`);
      return;
    }

    // Evidence is gathered while the model generates, so signing costs no extra
    // round trip, and the report data ties it to this client's nonce and request.
    const reportData = sha256(concat(nonce, hashRequest(raw)));
    const evidencePromise = deployment.attestation(reportData);
    evidencePromise.catch(() => undefined);
    const failed = response.status >= 400;

    if (failed || !response.contentType.includes('text/event-stream')) {
      // A buffered body can be hashed and signed before a single byte reaches
      // the client, so an unreceipted response is never observable.
      let body: Buffer;
      try {
        body = await collect(response);
      } catch (err) {
        upstreamError(reply, errorMessage(err));
        return;
      }
      reply.header('content-type', response.contentType);
      if (failed) {
        reply.status(response.status);
        reply.send(body);
        return;
      }
      let usage: CompletionUsage;
      try {
        usage = await response.usage;
      } catch (err) {
        upstreamError(reply, errorMessage(err));
        return;
      }
      if (usage.model.length > 0 && usage.model !== declared.id) {
        upstreamError(reply, `inference upstream served '${usage.model}' instead of '${declared.id}'`);
        return;
      }
      const receiptId = receiptIds.mint(receiptTag);
      // One body, one hash, one write: the marking member is inside the bytes before they are
      // digested, so there is no route by which a receipt is issued over a response that was never
      // marked, and none by which a client is sent bytes other than the ones it is vouched for.
      const marked =
        markingScheme === 'none'
          ? null
          : markBufferedBody(body, Math.floor(Date.now() / 1000));
      if (marked !== null && !marked.marked) {
        // The flag asked for a mark and this response's shape cannot carry one, which is a fact a
        // caller has to be told. Serving the body unmarked and signing `sch: none` would be true of
        // the bytes and false to the deployment's own configuration, and the reader who could act on
        // the difference is this one.
        upstreamError(reply, marked.why);
        return;
      }
      const sent = marked === null ? body : Buffer.from(marked.body);
      await issue({
        id: receiptId,
        nonce,
        requestBody: raw,
        responseHash: sha256(sent),
        modelId: declared.id,
        weights: declared.wts,
        evidence: await evidencePromise,
        usage,
        marking: marked === null ? unmarked() : marked.marking,
      });
      reply.header('x-ashaveri-receipt-id', receiptId);
      reply.send(sent);
      return;
    }

    const iterator = response.chunks[Symbol.asyncIterator]();
    const early: Buffer[] = [];
    // Hold the headers until the upstream has produced bytes, so an upstream that accepts the
    // connection and then says nothing is a 502 rather than a receipted empty 200. That is the one
    // job the old wait for a completion id did, and it is stated as a bytes check now that the id
    // arriving in those bytes names nothing this gateway looks up.
    try {
      while (early.length === 0) {
        const next = await withTimeout(iterator.next(), FIRST_EVENT_TIMEOUT_MS, 'inference upstream produced no response bytes');
        if (next.done === true) {
          break;
        }
        early.push(Buffer.from(next.value));
      }
    } catch (err) {
      upstreamError(reply, errorMessage(err));
      return;
    }
    if (early.length === 0) {
      upstreamError(reply, 'inference upstream produced an empty response body');
      return;
    }
    const id = receiptIds.mint(receiptTag);
    const hasher = createHash('sha256');
    // Only a gateway that marks holds back any part of a stream, and only its last frames: see
    // `MarkedStreamTail`.
    const tail = markingScheme === 'none' ? null : new MarkedStreamTail();

    // SSE is written to the raw response: Fastify's stream plumbing does not
    // reliably deliver a generator-backed body, and a completion whose bytes
    // never reached the client must not be receipted.
    reply.hijack();
    const res = reply.raw;
    res.writeHead(response.status, {
      'content-type': response.contentType,
      'x-ashaveri-receipt-id': id,
      'cache-control': 'no-cache',
    });
    // Set from the close listener below, so it is held as a property: a `let` written only
    // in a callback keeps the value it started with where the write loop reads it.
    const client = { aborted: false };
    res.once('close', () => {
      client.aborted = true;
    });

    const write = async (chunk: Uint8Array): Promise<void> => {
      hasher.update(chunk);
      if (res.write(chunk)) {
        return;
      }
      await new Promise<void>((resolve) => {
        const done = (): void => {
          res.off('drain', done);
          res.off('close', done);
          resolve();
        };
        res.once('drain', done);
        res.once('close', done);
      });
    };

    // A write of upstream bytes goes through the tail when this gateway marks, because the last frame
    // of a stream is the one place its mark has to sit ahead of, and through `write` either way, so
    // the hash and the socket see one sequence of bytes.
    const forward = async (chunk: Uint8Array): Promise<void> => {
      if (tail === null) {
        await write(chunk);
        return;
      }
      const ready = tail.writable(chunk);
      if (ready.length > 0) await write(ready);
    };

    try {
      for (const chunk of early) {
        await forward(chunk);
      }
      while (!client.aborted) {
        const next = await iterator.next();
        if (next.done === true) {
          break;
        }
        await forward(next.value);
      }
      if (client.aborted) {
        void iterator.return?.();
        return;
      }
      const usage = await response.usage;
      if (usage.model.length > 0 && usage.model !== declared.id) {
        res.destroy(new Error(`inference upstream served '${usage.model}' instead of '${declared.id}'`));
        return;
      }
      // The mark is the gateway's own bytes, added after the upstream's last byte and before the
      // digest is finalised, through the same closure that put every other frame on the socket. A
      // frame written from here on is inside `res`; one written in the `finally` below would not be,
      // which is why the closing byte is not where a mark belongs.
      let marking = unmarked();
      if (tail !== null) {
        const mark = markingFrame(declared.id, Math.floor(Date.now() / 1000));
        for (const piece of tail.finishing(mark.frame)) {
          await write(piece);
        }
        marking = mark.marking;
      }
      // Signed before the closing byte, so a client that reads to the end and
      // immediately fetches its receipt cannot lose the race.
      await issue({
        id,
        nonce,
        requestBody: raw,
        responseHash: new Uint8Array(hasher.digest()),
        modelId: declared.id,
        weights: declared.wts,
        evidence: await evidencePromise,
        usage,
        marking,
      });
    } catch (error) {
      res.destroy(error instanceof Error ? error : new Error(errorMessage(error)));
    } finally {
      if (!res.writableEnded && !res.destroyed) {
        res.end();
      }
    }
  });

  // Assigned rather than decorated, so the method's type lives on GatewayInstance and nowhere in
  // Fastify's own interface.
  return Object.assign(app, { scopeCheckedRoutes: (): string[] => [...checkedPaths].sort() });
}
