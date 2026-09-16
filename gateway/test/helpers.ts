import {
  EMPTY_BODY_SHA256_HEX,
  sha256Hex,
  signPopAuthorization,
  signingKeyFromSeed,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';
import { buildGateway, type GatewayInstance, type GatewayOptions } from '../src/server.js';
import {
  CredentialStore,
  newBearerCredential,
  newPopCredential,
  type CredentialRecord,
  type Scope,
} from '../src/access.js';
import { openMemoryAccessLog, type MemoryAccessLog } from '../src/aclog.js';
import { sha256 } from '../src/digest.js';

export const CLOCK_SECONDS = 1_772_000_000;

/**
 * The one seed rule behind every fixture key pair: the id's own bytes, so two fixtures whose ids
 * happen to be the same length still hold different keys. A seed read off the length let either of
 * them sign as the other, and an assertion about one credential's admission would then have been
 * an assertion about the other's key.
 */
function seedOf(id: string): Uint8Array {
  return sha256(new TextEncoder().encode(id));
}

export interface Generated {
  record: CredentialRecord;
  privateKey: Uint8Array;
}

/** One generation per cell, so a nonce cannot leak between two assertions. */
export function generated(id: string, scopes: Scope[], extra: Partial<CredentialRecord> = {}): Generated {
  const fresh = newPopCredential({ id, scopes, now: CLOCK_SECONDS });
  const seed = seedOf(id);
  return {
    record: { ...fresh.record, publicKey: signingKeyFromSeed(seed).publicKey, ...extra },
    privateKey: seed,
  };
}

export interface Harness {
  app: GatewayInstance;
  log: MemoryAccessLog;
  records: CredentialRecord[];
  /**
   * The store this harness made, whose start-up read a test that writes a credential file has to
   * perform itself; the gateway only reloads a file it already served.
   */
  store: CredentialStore;
  /**
   * A header for one request. `key` is for a header naming a record this harness holds no key
   * for: without it, `unsignedKeyFor` refuses the id as an admission a test has no business
   * inventing.
   */
  signFor(
    id: string,
    method: string,
    target: string,
    body: string | null,
    options?: { ts?: number; nonce?: Uint8Array; key?: Uint8Array },
  ): Record<string, string>;
  inject(options: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    payload?: string;
  }): Promise<{ statusCode: number; json: { error?: { code?: string } } & Record<string, unknown> }>;
}

export interface HarnessInput {
  /** PoP credentials: the harness holds both halves, so `signFor` can sign for them. */
  credentials?: Generated[];
  /** Records with no key behind them: bearer credentials, and revoked ones. */
  extra?: CredentialRecord[];
  allowBearer?: boolean;
  toleranceSeconds?: number;
  /**
   * What `buildGateway` takes besides the two access options. The suites that serve a live
   * deployment, an upstream backend or a bounded receipt store need a route through here, because
   * a second construction path outside `harness()` is exactly what this file exists to prevent.
   */
  gateway?: Partial<Omit<GatewayOptions, 'access' | 'accessLog'>>;
  /**
   * A credential file on disk to build the store from, for a test whose point is the reload the
   * gateway performs. The store is still made here, so the pinned clock, the tolerance and the
   * bearer rule are the ones every other harness gets. `credentials` has to name the records that
   * file carries, because that is where `signFor` reads keys from.
   */
  storePath?: string;
}

const NONCE_BYTES = 16;
/** The prefix every implicit nonce carries, so a failure names a harness nonce at a glance. */
const NONCE_TAG = 0x33;

export async function harness(input: HarnessInput = {}): Promise<Harness> {
  const credentials = input.credentials ?? [];
  const records: CredentialRecord[] = [...credentials.map((each) => each.record), ...(input.extra ?? [])];
  const keys = new Map<string, Uint8Array>(credentials.map((each) => [each.record.id, each.privateKey]));
  // One construction site, so the clock, the tolerance and the bearer rule below are the ones every
  // harness runs on: a store a caller built for itself would carry its own, and the pinned instant
  // `signFor` stamps at would no longer be the one the floor reads.
  const store = new CredentialStore({
    ...(input.storePath === undefined ? { file: { version: 1, credentials: records } } : { path: input.storePath }),
    allowBearer: input.allowBearer,
    toleranceSeconds: input.toleranceSeconds,
    // `signFor` stamps every header at CLOCK_SECONDS, so the store has to read the same instant: on
    // the wall clock it would refuse a well-signed request as months stale, and the tolerance test
    // would measure the age of the fixture rather than the offset it names. A test that wants a
    // different instant asks for one with `ts`, which is what that parameter is for.
    now: () => CLOCK_SECONDS * 1000,
  });
  // Two clocks run through a harness, and only one of them is pinned. The store's `now`, set just
  // above, answers one question: is this stamp inside the window. The access record's `t` and `dur`
  // are stamped by the flush off the wall clock this process runs on, which a memory log carries
  // without ever reading them back. A suite that wants a fixed instant in a written line has to
  // bring its own log rather than assume the clock here reaches the record.
  const log = openMemoryAccessLog();
  const app = buildGateway({ ...input.gateway, access: store, accessLog: log });
  // The replay key is a credential id and a nonce, so one nonce used twice by the same credential
  // is a 409 whatever the two requests were for. Counting here rather than at every call site keeps
  // "sign me a header for this request" a question about one request instead of a bookkeeping task.
  let signed = 0;
  function implicitNonce(): Uint8Array {
    const bytes = new Uint8Array(NONCE_BYTES).fill(NONCE_TAG, 0, 12);
    const at = signed;
    signed += 1;
    bytes[12] = (at >>> 24) & 0xff;
    bytes[13] = (at >>> 16) & 0xff;
    bytes[14] = (at >>> 8) & 0xff;
    bytes[15] = at & 0xff;
    return bytes;
  }
  /**
   * A header naming a credential this store never carried is the one refusal a test can be asked to
   * produce without holding anything: nothing is protected by a key that does not exist, so the same
   * seed rule `generated()` follows is re-derived here. An id that *is* in the store with no key in
   * `keys` is a different matter. That record arrived through `extra` because its secret belongs
   * to someone else, and signing as it would be a test inventing an admission.
   */
  function unsignedKeyFor(id: string): Uint8Array {
    if (records.some((entry) => entry.id === id)) {
      throw new Error(`harness: ${id} is in the store but its key is not held here`);
    }
    return seedOf(id);
  }
  return {
    app,
    log,
    records,
    store,
    signFor(id, method, target, body, options) {
      const nonce = options?.nonce ?? implicitNonce();
      const fields: PopFields = {
        ts: options?.ts ?? CLOCK_SECONDS,
        nonce,
        method,
        target,
        bodyDigestHex: body === null ? EMPTY_BODY_SHA256_HEX : sha256Hex(new TextEncoder().encode(body)),
      };
      // A key from the caller is the one case `unsignedKeyFor` cannot serve: a header naming a
      // record whose admission the floor refuses before it looks at the signature.
      const key = options?.key ?? keys.get(id) ?? unsignedKeyFor(id);
      return {
        authorization: signPopAuthorization(fields, id, key),
        'x-ashaveri-nonce': toBase64Url(nonce),
      };
    },
    async inject(options) {
      // Fastify chooses its body parser from the media type, and it does so before the floor runs,
      // so a request that carries a body and no content type is a 415 that never reaches a check.
      // The bytes signed are the bytes sent, which is why the digest is taken over `payload` here
      // and nowhere over this header.
      const headers: Record<string, string> = {
        ...(options.payload === undefined ? {} : { 'content-type': 'application/json' }),
        ...options.headers,
      };
      const response = await app.inject({
        method: options.method as 'GET',
        url: options.url,
        headers,
        ...(options.payload === undefined ? {} : { payload: options.payload }),
      });
      return {
        statusCode: response.statusCode,
        // Two routes answer with an evidence document rather than JSON, and a cell that reads a
        // refusal out of a document body is asking for nothing. An empty object is that nothing.
        json: parseBody(response.payload),
      };
    },
  };
}

function parseBody(payload: string): { error?: { code?: string } } & Record<string, unknown> {
  if (payload.length === 0) return {};
  try {
    return JSON.parse(payload) as { error?: { code?: string } } & Record<string, unknown>;
  } catch {
    return {};
  }
}

export { newBearerCredential, newPopCredential };
