import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { createHash, randomUUID } from 'node:crypto';
import { Transform } from 'node:stream';
import { evidenceReportData } from '@ashaveri/attest-core';
import {
  hashRequest,
  isEventStream,
  issueReceipt,
  randomNonce,
  sealDeploymentManifest,
  type CollateralValidityAnchor,
  type Marking,
  type MarkingScheme,
  type ReceiptPayload,
  type ReceiptPayloadV1,
  type ReceiptPayloadV2,
  type SigningKey,
  type TeeKind,
  type TokenMetering,
} from '@ashaveri/receipt';
import type { AccessLog, AccessRecord } from './aclog.js';
import {
  AccessError,
  ReceiptNamespace,
  TokenBucket,
  requireRouteScope,
  type CredentialRate,
  type CredentialStore,
} from './access.js';
import { anchorFrom, readFailedAnchor, type AppraisalReader } from './appraisal-cache.js';
import { fromBase64Url, toBase64Url } from './b64.js';
import { mockBackend, type BackendResponse, type CompletionBackend, type CompletionUsage } from './backend.js';
import { mockDeployment, type AttestationBundle, type Deployment } from './deployment.js';
import { fromHex, sha256, toHex } from './digest.js';
import { EpochJournalError, unsealedHistoryRefusal, type EpochJournal, type EpochJournalEntry } from './epoch-journal.js';
import { stampDisclosureOf } from './issuance-disclosure.js';
import { StreamedItemStamps, boundStampsAt, stampedBufferedItem, type FramedItemStamps } from './item-stamps.js';
import { markBufferedBody, markingFrame, unmarked } from './marking.js';
import {
  parseChatCompletionRequest,
  readChatCompletionHead,
  RequestError,
  type ChatCompletionHead,
  type ChatCompletionRequest,
  type ChatMessage,
} from './mock.js';
import { ResidentBodyBudget, type ResidentBodyReservation } from './resident-body.js';
import { AsyncMarkedStreamTail, StreamCompletionGate } from './stream-completion.js';
import {
  HOST_CLOCK_SOURCE,
  measurableSpanSeconds,
  openMemoryReceiptStore,
  receiptsNeededForWindow,
  sourceSentence,
  type ReceiptRetention,
  type ReceiptStore,
  type RetainedWindow,
  type TimeSource,
} from './store.js';

const NONCE_BYTES = 16;
// A cold model load can hold back the first streamed event for minutes.
const FIRST_EVENT_TIMEOUT_MS = 120_000;
/**
 * The largest response body this process collects at once.
 *
 * A buffered completion is read whole before a byte of it reaches the client, because the digest the receipt
 * signs and the item it stamps are cut out of those bytes. Past this bound the answer is refused rather than
 * held, with `RESPONSE_TOO_LARGE`, which is the refusal a caller can name: what is short is a bound this build
 * ships, not a fault of the inference server, and the two answers are not the same thing to whoever reads one.
 * A streamed completion is never collected, so this bound reaches no part of it: its frames are forwarded and
 * hashed as they arrive. An answer this route will not sign is read whole whatever the request asked for,
 * because there is nothing to attest from its bytes and no stream arm to hand them to, which is why the
 * refusal states two shapes of advice rather than one. `collect` below writes the answer, and
 * `docs/configured-values.md` states the number. Exported for the same reason
 * `STREAM_USAGE_INJECTION_MAX_BYTES` is: the two cells that hold the bound are written against it rather than
 * against a literal copied out of this file.
 */
export const MAX_BUFFERED_BODY = 32 * 1024 * 1024;
/**
 * What a run that named no request body bound reads: 128 MiB, and exported for the reason
 * `MAX_BUFFERED_BODY` is, so the cell that proves the shipped figure reads it off this line rather than
 * repeating a literal that can drift from it.
 *
 * The number was 16 MiB, and that default was the reason a customer's own payload could be refused by this
 * gateway rather than by the inference server they chose: the bound is a ceiling on what this process takes
 * in, so a body past it never reaches that server, and the answer it gets is a 413 about a number nobody
 * serving them picked. The standing condition for this area is that a gateway must not be the tightest
 * constraint on a request it serves, and 128 MiB is what the estate reads as clearing the asks its customers
 * send today with room to spare.
 *
 * What makes the raised figure affordable is a different number, and it is not this one: this bound says how
 * large one body may be, and the resident request-body budget beside it says how many such bodies one process
 * will hold at once. A deployment that raised this bound and ran no budget would be holding a customer's
 * whole payload in memory for the life of the request and shedding on the first out-of-memory kill rather
 * than on a refusal an operator chose.
 */
export const DEFAULT_REQUEST_BODY_LIMIT_BYTES = 128 * 1024 * 1024;
/**
 * The bound this deployment's own environment states, or nothing where it states none. Read where the bound
 * is read rather than at the command line, because it bounds the reader this process builds and a library
 * caller that passed the option never has to know the variable exists. A value that is not a positive whole
 * number of bytes stops the build: a bound the process could not state is not a bound it may serve on, and
 * falling back to the shipped one here would run a deployment that believes it set another.
 */
function requestBodyLimitFromEnvironment(): number | undefined {
  const stated = process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'];
  if (stated === undefined || stated.length === 0) return undefined;
  const parsed = Number(stated);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new RangeError(
      `ASHAVERI_REQUEST_BODY_LIMIT_BYTES states '${stated}', and a request body bound is a positive whole number of bytes`,
    );
  }
  return parsed;
}
/**
 * What a run that named no resident request-body budget reads: 512 MiB of request bodies held at once, which is
 * four of the largest bodies this gateway will read.
 *
 * The figure is arithmetic on the two numbers beside it and not a measurement. It says that one process will
 * hold up to four bodies of `DEFAULT_REQUEST_BODY_LIMIT_BYTES` at once, and it keeps nothing outside that sum
 * for the copies the serving path makes while it digests and forwards the bytes, nor for the answer coming back
 * from the upstream, which `MAX_BUFFERED_BODY` bounds rather than this constant. What a held body really costs
 * this process beyond its own bytes, and how many of them a process can hold before holding stops being what
 * limits it, are a concurrency question, and no run of it is recorded in this repository: the memory one
 * deployment is given is another, and the deployment text this repository publishes states neither.
 *
 * So an operator reads this as a ceiling on request bodies held, chosen so that a deployment knows what it has
 * agreed to and can raise or lower it against the memory it actually has, and not as a capacity figure this
 * build measured. A deployment with less memory than four such bodies and the copies they cost states a smaller
 * budget, and the refusals move from the caller's wait to the operator's number, which is the point of the
 * number existing at all.
 */
export const DEFAULT_REQUEST_BODY_BUDGET_BYTES = 512 * 1024 * 1024;
/**
 * The budget this deployment's own environment states, or nothing where it states none. Read the same three
 * ways as the bound above it, for the same reasons: the option belongs to a library caller who knows what it
 * wants, the variable belongs to a container that says nothing about itself at the command line, and a value
 * that is not a positive whole number of bytes stops the build rather than falling back, because a deployment
 * that believes it bounded its memory and is running on another bound is the configuration nobody wrote.
 */
function requestBodyBudgetFromEnvironment(): number | undefined {
  const stated = process.env['ASHAVERI_REQUEST_BODY_BUDGET_BYTES'];
  if (stated === undefined || stated.length === 0) return undefined;
  const parsed = Number(stated);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new RangeError(
      `ASHAVERI_REQUEST_BODY_BUDGET_BYTES states '${stated}', and a resident request-body budget is a positive whole number of bytes`,
    );
  }
  return parsed;
}
/** Evidence is addressed by the digest it binds to, which is what its URL says. */
const REPORT_DATA_HEX = /^[0-9a-fA-F]{64}$/;
/** A weights manifest is addressed by the digest a receipt's `wts` carries: 32 bytes, 64 hex characters. */
const WEIGHTS_DIGEST_HEX = /^[0-9a-f]{64}$/;

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
   * The durability guard read at admission. Absent means nothing is refused on it, which is what a
   * deployment that configures nothing runs: `gateway/src/cli.ts` hands this option the same
   * retention object it opened the store with, so a process serving traffic compares a period and a
   * count it did not have to state twice.
   */
  readonly receiptIntakeGuard?: ReceiptIntakeGuard;
  /**
   * The deployment-wide bound on the completions this process admits, read at admission ahead of the
   * upstream call and refused with `DEPLOYMENT_RATE_LIMITED`. Absent means `DEFAULT_COMPLETION_RATE`, the
   * ceiling this build measures on its own completion path, so a deployment that configures nothing
   * is held to what it can actually serve rather than to a number nobody chose. `gateway/src/cli.ts` hands
   * this the rate its `--completion-rate` flag names.
   */
  readonly completionBound?: DeploymentCompletionBound;
  /**
   * The largest request body this process reads, in bytes. It bounds the reader every route shares, so a body
   * past it is answered before a route runs, with `BODY_TOO_LARGE` and the shape the route gives its own
   * refusals, and it is a refusal rather than a truncation: nothing is forwarded and no receipt is issued for
   * bytes this process would not read. Absent means the bound this deployment's environment states, and absent
   * there too means `DEFAULT_REQUEST_BODY_LIMIT_BYTES`, so a run that set neither reads what it has always
   * read.
   */
  readonly requestBodyLimitBytes?: number;
  /**
   * The request-body bytes this process will hold at once, summed across the requests in flight. Where
   * `requestBodyLimitBytes` bounds one body, this bounds how many of them are resident together, and it exists
   * because the bound above it says nothing about that sum: a body stays held for the whole life of its
   * completion, since the receipt signs those bytes and the upstream is forwarded them, so a deployment that
   * raised the one without stating the other would be sizing its memory against its busiest minute rather than
   * against a number it chose.
   *
   * A caller is admitted while the bytes already resident plus this request's stay within the budget, and the
   * refusal is `RESIDENT_BODY_BUDGET_EXCEEDED`, retryable, at the reader and ahead of every credential check
   * for the reason `docs/access-control.md` section 1 states. Absent means the budget this deployment's
   * environment states, and absent there too means `DEFAULT_REQUEST_BODY_BUDGET_BYTES`. There is no spelling
   * that takes the budget off, and a large number is how a deployment says it does not want it: the bound is
   * what makes a raised body limit safe, so the option that removes it would remove the reason for the raise.
   */
  readonly requestBodyBudgetBytes?: number;
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
   * There is no spelling of this option that leaves the marking field out of a receipt. Every payload
   * this format writes carries one, because an absent `mk` would read to a verifier as "unmarked" and as
   * "this build predates marking" at once, which is the silence the member exists to refuse.
   */
  readonly marking?: MarkingScheme;
  /**
   * This process's one time source: a name, the bound that source can be wrong by, and the reading
   * every whole-second stamp in this file is taken from. The issuance instant a receipt claims, the
   * stamp the store files the record under, the instant a marking frame carries, and the arrival stamp
   * on every access log line all come from here, so the moment a receipt claims cannot be moved apart
   * from the moment the filing cabinet says it arrived by taking them at two moments, and neither is
   * decided by a call the deployment cannot reach.
   *
   * Absent means `HOST_CLOCK_SOURCE`: this host's own clock, at the uncertainty nobody measured. That is
   * a stated default rather than an implied one, because a deployment that wires nothing should be read
   * as claiming a host claim rather than a measured one.
   *
   * Handing over a source is not the same as making a stamp unmovable. A process can only read the clock
   * it was given, so on a deployment where whoever owns the host also chose the clock, this option moves
   * the move rather than preventing it: what it buys is that the choice is written down once at
   * construction, that a deployment able to read an attestable or ratcheted time can name it and state
   * its bound here, and that the stamp of a record is a thing a test can fix without waiting. Section 3
   * of `docs/receipt-spec.md` states what an `iat` therefore proves and what it cannot.
   */
  readonly time?: TimeSource;
  /**
   * The reader of a cached appraisal, wired by a deployment whose appraiser runs on a schedule outside
   * this process. Absent means no cache, and an issuance then signs the anchor of a gateway that took
   * nothing in: `notTakenInAnchor`, byte for byte the anchor a deployment that configures nothing signs.
   *
   * Wiring one does not put a vendor on any request path, because the reader answers out of a cache
   * something else filled and `issue` only converts what it answered. The two things a reading is weighed
   * against are the two instants it carries: an entry whose own window had closed is answered as the
   * absence its numbers state rather than signed as a digest of bytes nobody can weigh, and a reader that
   * throws is logged at the site and answered the same way, so an issuance neither fails on a cache nor
   * borrows a word from one. What the anchor states about the instants it quotes is whose clock they came
   * from, and none of them is this process's: `iat` and `sd` stay the readings of `time` and are the only
   * instants of an issuance this gateway takes itself.
   */
  readonly appraisal?: AppraisalReader;
  /**
   * The epochs this deployment has signed under, read from the journal it keeps beside its receipts.
   *
   * Present means `keys[]` is published from that history: every entry the journal holds becomes a row, and
   * each row states the epoch it signed under and the first instant this deployment accepted a signature from
   * it, which is what lets a reader weigh a receipt from before a rotation against the window its own epoch
   * was served in. Absent is today's document: the one key this process holds, no epoch member and no window,
   * which a client reads as a deployment that has published no history rather than as one whose key has
   * always been the key.
   *
   * A journal is written by the process it describes, so handing this option a history that does not name the
   * running key and epoch is not a state a deployment can reach through `gateway/src/cli.ts`, and it is not a
   * state this build checks for: what the served document would then mean for a reader is decided by
   * `parseManifest` at that reader, which is where the rules about the shape of a history live.
   */
  readonly epochJournal?: EpochJournal;
}

export interface ManifestJson {
  readonly v: 1;
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
  /**
   * The keys this deployment signs receipts with, and for a deployment that keeps an epoch journal the whole
   * history of them. The two optional members travel together, as section 4.4 of `docs/receipt-spec.md`
   * states, and a row that carries one without the other is a manifest that began declaring windows and
   * stopped halfway: `parseManifest` refuses that document, and this build never writes one.
   */
  readonly keys: readonly {
    kid: string;
    alg: 'Ed25519';
    publicKey: string;
    epk?: number;
    validFrom?: number;
  }[];
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
  /**
   * What this process holds of the resident request-body budget right now, in bytes. The figure is the sum the
   * refusals above are decided from, so this is the one way to ask a running gateway what it is holding rather
   * than what it thinks it should be holding.
   *
   * It is on the instance for the same reason `scopeCheckedRoutes` is: the fact it reports is process state no
   * response carries, and the cells that prove a charge was given back have to read the integer itself rather
   * than infer it from whether some later request happened to be refused, which is an inference that goes green
   * whenever a test's timing happens to work. Its only consumer today is `test/resident-body-budget.test.ts`:
   * nothing this gateway ships reads the figure and no route answers with it, so this is a window onto the
   * process opened for the suite that has to see inside it, not an observability surface a deployment is asked
   * to rely on.
   */
  residentBodyBytes(): number;
};

/**
 * A reply body is one line of whatever log the client keeps, and `JSON.stringify` is silent on U+2028 and
 * U+2029, so text that arrives standing as it was goes into a message as a second line. One site needs
 * this: a model name read out of a JSON body, which `JSON.parse` hands over unchanged. The request-chosen
 * text elsewhere is already held by something measured, not assumed. A socket carrying either separator in
 * a request line or a header name is refused 400 before a route runs, and a target quoted back by
 * admission therefore only ever holds the percent-encoded spelling; a credential id passes a character rule
 * on the way in and on the way out; and the parser packages escape these two where they build a message.
 *
 * This is a fourth copy of the printed-line ranges rather than the same rule as the others. The owner of the
 * class inside the receipt package is `packages/receipt/src/line-text.ts`, the CLI and `attest-core` state
 * their own copies beside their own boundaries, and this one differs from all three in two ways, both
 * deliberate here. It is narrower: the tag block `U+E0000..U+E007F` is not spelled out, so those code points
 * are caught only for as long as the runtime's tables classify them as format characters, which is the
 * reliance the owner refuses about its own class. And it rewrites instead of refusing or escaping: a
 * character it removes leaves a space behind, so a value carrying a line separator and a value carrying a
 * space leave this gateway as one visible string.
 *
 * The question that copy answers is whether a gateway input owes the estate's printed-line rule, and the answer
 * is that this one does not. A reply body naming a model the caller typed is not evidence: it is not signed, not
 * inventoried, and not printed beside an attestation, and the request-chosen spelling is answered by a rule of
 * its own before this line is reached, because admission compares it whole against the ids the deployment
 * declares and answers 400 when nothing matches, which a name carrying an invisible member of the class does
 * not. What travels into a receipt is the declared id rather than the requested spelling, so the unprintable
 * request stays a line of the error that refused it and becomes no row of any signed document. Where the class
 * does reach this path is the deployment's own list: a declared model id is what `mdl` carries, and
 * `assertLineSafeText` (`packages/receipt/src/receipt.ts`) refuses a payload whose `mdl` carries one of those
 * characters at the step that signs, so an unprintable id is a boot-time or issuance refusal on this side of
 * the wire and not a silence.
 *
 * What the narrower copy leaves, and what a reader of this note should weigh rather than fix in passing, is the
 * rewrite's own lossiness. A removed character leaves a space behind, so two request names differing by one
 * member of the class print as one sentence, and anything a deployment copies out of that sentence carries a
 * string whose extent nobody can recover from it. Two changes would close that: building this copy from
 * `FORGES_A_LINE_RANGES`, which the class owner publishes,
 * or escaping what is removed the way `packages/receipt/src/errors.ts` escapes it, so a message states the
 * character it cut instead of hiding it. Neither is taken here, because this site answers for one line of a
 * client's log and not for a document a reviewer cites, and the exposure is the copying, not the rewriting.
 */
function asOneLine(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, ' ');
}

async function upstreamError(reply: FastifyReply, message: string): Promise<void> {
  await reply.code(502).send({ error: { message, type: 'upstream_error' } });
}

/**
 * The members of a payload that decide the value its evidence is bound to: which document this issuance
 * signs, the request nonce, the digest of the exact request bytes, and the session key a document naming an
 * arm carries. Typed out of the two payload versions themselves, so the pair the fold reads and the pair the
 * signature covers cannot be spelled apart: a version 1 holding a key, or a version 2 naming none, is not a
 * state this type can write, which is why nothing below refuses one.
 *
 * Minted while the request is the only fact this process holds, because the evidence is gathered while the
 * model generates and signing must not cost a round trip, and spread into the document by the issuance that
 * files it. So the value a platform quote is asked to seal is read out of the same fields the receipt states
 * rather than restated beside them: a served receipt cannot name a nonce, a request digest or an arm that was
 * not the one its own quote was bound to.
 */
type PayloadIdentity =
  | Pick<ReceiptPayloadV1, 'v' | 'nce' | 'req'>
  | Pick<ReceiptPayloadV2, 'v' | 'nce' | 'req' | 'enc'>;

/**
 * This gateway signs the document that names no arm, because it holds no session key to write into one, so
 * the challenge is the two-part reading and every part of it is this request's own. A deployment that begins
 * to seal a prompt moves this line and the fold follows it; that is the whole of what the mint is asked to
 * hold, and it is why the fold sits on these members rather than beside them.
 */
function mintIdentity(nonce: Uint8Array, requestBody: Uint8Array): PayloadIdentity {
  return { v: 1, nce: nonce, req: hashRequest(requestBody) };
}

/**
 * The value this issuance's evidence has to carry, reached through the one derivation the shipped reader
 * runs as well. The arm comes out of the payload identity above and not from a caller's argument, so the
 * reading a stranger recomputes from a receipt and the reading made here are the same call over the same
 * fields.
 */
function reportDataFor(identity: PayloadIdentity): Uint8Array {
  return evidenceReportData(identity.nce, identity.req, identity.v === 2 ? identity.enc : undefined);
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

/**
 * The `tok` pair of a receipt, taken from the one value a backend settled.
 *
 * Both figures move together because the usage event that carries them does, which is the rule the format
 * states and the writer enforces: a count beside an absence is refused rather than signed. `CompletionUsage`
 * offers the same two arms and nothing between them, so a half-reported pair is not a value this reads. What
 * remains is a projection: the guard settles which arm the checker is reading, and each arm hands over the
 * pair as it was settled, so the answer to a pair this build cannot name is the pair that arrived rather than
 * an absence decided here. Nothing about either reachable state moves: a completion whose upstream reported
 * nothing signs two nulls, and one that reported zero tokens signs two zeros.
 */
function meteringOf(usage: CompletionUsage): TokenMetering {
  if (usage.completionTokens === null) {
    // The absence arm, and by the type the arm both figures are in.
    return { p: usage.promptTokens, c: null };
  }
  return { p: usage.promptTokens, c: usage.completionTokens };
}

/**
 * Which answer `collect` is holding.
 *
 * The route collects both: a completion it is about to sign, and the inference server's own failure, whose
 * body is handed back as it arrived. The bound is one number and the advice is not, because the shape of a
 * request decides what a completion is answered with while nothing about a request decides what a failure is
 * answered with.
 */
type CollectedAnswer = 'completion' | 'upstream-failure';

async function collect(response: BackendResponse, answer: CollectedAnswer): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of response.chunks) {
    size += chunk.byteLength;
    if (size > MAX_BUFFERED_BODY) {
      throw bufferedResponseTooLarge(size, answer);
    }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, size);
}

/** The mebibyte spelling of a bound, so a sentence states the number the constant holds. */
function mebibytes(bytes: number): string {
  return String(bytes / (1024 * 1024));
}

/**
 * The refusal `collect` answers with: the bound this process ships, the size this answer reached, and what a
 * caller can do about it. An untyped error here was read by the generic handler as a fault of the inference
 * server, which told a caller nothing it could act on and told an operator their installation was broken over
 * a number this build chose.
 *
 * The two answers get two sentences because the one change of shape that gets a completion past the bound is
 * no change at all for a failure. A completion asked for streamed is forwarded as it arrives and never
 * collected, so the bound reaches no part of it; the inference server's own refusal is read whole whatever the
 * request asked for, because nothing is being attested from its bytes and the route has no stream arm to hand
 * it to. Telling a caller to stream an error body would send it back with the same request and the same
 * answer, which is the failure mode the sentence exists to avoid.
 */
function bufferedResponseTooLarge(reachedBytes: number, answer: CollectedAnswer): AccessError {
  const bound =
    `The bound is MAX_BUFFERED_BODY, stated in docs/configured-values.md, shipped at ` +
    `${mebibytes(MAX_BUFFERED_BODY)} MiB and reached by no flag. `;
  if (answer === 'upstream-failure') {
    return new AccessError('RESPONSE_TOO_LARGE', {
      detail:
        `this gateway collects no answer past ${String(MAX_BUFFERED_BODY)} bytes, and the inference server's ` +
        `own failure had reached ${String(reachedBytes)} while it was being read, so none of it was handed on ` +
        `and nothing was signed: this is not a completion and never was one. ${bound}Asking for the completion ` +
        `streamed reaches nothing here, because the bytes past the bound are the upstream's failure rather ` +
        `than an answer a stream would carry, so what moves is this process's bound or the size of the ` +
        `failure the inference server returned`,
    });
  }
  return new AccessError('RESPONSE_TOO_LARGE', {
    detail:
      `this gateway collects no buffered completion past ${String(MAX_BUFFERED_BODY)} bytes, and this one had ` +
      `reached ${String(reachedBytes)} while it was being read, so the answer was refused before any of it was ` +
      `signed: no receipt was issued, and none of the upstream's bytes were handed on. ${bound}A caller asks ` +
      `for less of this deployment's answer, or asks for it streamed: a streamed response is forwarded as it ` +
      `arrives and never collected, so this bound reaches no part of it`,
  });
}

/**
 * The request as a backend reads it.
 *
 * The scan above already settled the grammar and took the two fields this route weighs, so the message
 * graph is built here only if the backend reaches for it: the one that forwards these bytes to an inference
 * server asks the same two questions the scan answered and nothing else, and holding the graph of a body
 * whose bulk is one inline file for the life of a completion is the cost the scan exists to remove. The
 * backend that reads messages is the mock, whose answer is about them, and for it this costs exactly what
 * the route paid before the scan existed.
 */
function requestForBackend(raw: Buffer, head: ChatCompletionHead): ChatCompletionRequest {
  let messages: readonly ChatMessage[] | undefined;
  return {
    model: head.model,
    stream: head.stream,
    get messages(): readonly ChatMessage[] {
      messages ??= parseChatCompletionRequest(JSON.parse(raw.toString('utf8'))).messages;
      return messages;
    },
  };
}

/**
 * The intake guard: the durability bound read while serving rather than only at an opening.
 *
 * The two numbers are the pair `gateway/src/store.ts` already compares when a file store opens, and
 * this is that arithmetic seen from outside the store: the retained set, the span its own stamps
 * cover, and the count the configured period takes at the rate those stamps measure. What it was for
 * is the difference between the two moments. An opening refuses a pairing it can no longer honour,
 * which is correct and too late for the window in force, because a store that reached the pairing
 * while serving keeps answering completions throughout it and the window a client was told about is
 * the shorter one the bound leaves. So the same fact, met at admission, is acted on there: a
 * completion is refused before the upstream is called, and reads, verification and handover keep
 * serving off the receipts already filed.
 */
export interface ReceiptIntakeGuard {
  /**
   * The durability policy this deployment configured, as the same object the receipt store was opened
   * with. A store reports its retained set and not its own configuration, so the two numbers the
   * guard compares have to be handed over; passing the very object a store was built from is what
   * keeps a refusal from being raised against a bound nothing was retired by.
   *
   * Both halves are needed. A policy bounded only by count, or only by a period, has no pairing to
   * contradict and is never refused here, exactly as the opening never asks. The `time` the same
   * interface carries is read for the bound its source declares and never for its instant: this compares
   * stamps a store has already written, and inventing a second clock to age them by would be a second
   * answer to a question the file has settled.
   */
  readonly retention?: ReceiptRetention;
  /**
   * The fraction of the durability bound at which the guard starts reading, in the half-open interval
   * (0, 1]. Default: 1, which is the bound itself.
   *
   * Because a retained set never exceeds its bound, a threshold at the bound is reached on exactly
   * one state, `count === maxCount`, which is the state the opening refusal already compares. The
   * default is therefore not a claim that the two agree in prose but a consequence of one arithmetic,
   * and `test/intake-guard.test.ts` holds it against a real store that refuses, or does not refuse,
   * to open on the same file. A deployment that sets nothing sees no change; a deployment that sets
   * half of it starts refusing when half its volume is retained, which is the point of the number
   * being a fraction rather than a constant.
   */
  readonly refusesAtFraction?: number;
  /**
   * The explicit opt-in to grow past the guard, off unless a deployment says so. With it set nothing
   * is refused at admission and issuance keeps filling the store while the bound retires the oldest
   * prefix, which is the behaviour this guard exists to stop, and its cost arrives inside a write:
   * the window served is the shorter one the bound reaches, and the next restart of that same volume
   * refuses to open rather than serve it. It is offered because a deployment that would rather pay
   * that than refuse a completion is making a capacity decision nobody here can make for it.
   */
  readonly growPastGuard?: boolean;
}

/** The numbers a refusal is made of, so the sentence names them and no reader re-derives them. */
export interface IntakeGuardFigures {
  /** Receipts retained now. */
  readonly retained: number;
  /** The count at which this guard starts reading, which is the threshold applied to the bound. */
  readonly refusesAt: number;
  /** The durability bound configured beside the period. */
  readonly bound: number;
  /** Seconds between the oldest and newest stamp in the retained set, as those two stamps read. */
  readonly spanSeconds: number;
  /** The seconds of that span the source supports a rate over, which is the denominator `needed` uses. */
  readonly spanSupportSeconds: number;
  /** The source those stamps came from, named as the store was told to name it. */
  readonly source: string;
  /** Seconds a reading of that source can be away by, or null when nobody measured it. */
  readonly uncertaintySeconds: number | null;
  /** The configured period. */
  readonly periodSeconds: number;
  /** What that period takes at the rate the span the source supports measures. */
  readonly needed: number;
  /**
   * Entries of the retained set that a retirement suspension keeps, which the configured bounds alone
   * would have given up. Zero says the set is what its own bounds reach: traffic, and not an instruction
   * handed to the store, is what grew it to the point this guard is reading.
   */
  readonly retainedBySuspension: number;
}

/**
 * The threshold a deployment that configures nothing runs at: the durability bound itself, which is
 * the only point at which the guard's answer and the store opening's answer are the same sentence.
 */
export const DEFAULT_INTAKE_GUARD_FRACTION = 1;

/**
 * Whether this retained set has reached the point where honouring the period would retire a receipt
 * the period still covers, and the figures that say so. Null means serve.
 *
 * Four early returns, and each is one of the states that would otherwise refuse a quiet deployment.
 * Growing past the guard is an opt-in read first, because a deployment that took it has refused this
 * decision rather than asked for it later. One bound alone is not a pairing. A retained set that has
 * not reached the configured point of the bound is shedding nothing, however slow it is, and a store
 * that has filed fewer than two receipts, or was given no period, has measured no rate for the count
 * to be derived from. And a retained set at its bound whose stamps already span the period is holding
 * what it asked for at the traffic it carries, which is the case the opening lets through and this
 * must too.
 *
 * What survives those four is the pairing itself, and the answer is the store's own arithmetic:
 * `receiptsNeededForWindow` is the function `assertWindowHeldable` refuses by, imported rather than
 * copied so the two moments cannot drift apart and an operator cannot be told one count by a banner
 * and another by a refusal.
 *
 * How much of the retained set a suspension keeps is not arithmetic this function can do: it reads a
 * window of bounds and a count, and the index the question is about belongs to the store that handed
 * them, so the count arrives as an argument. A caller that has no store reading hands nothing, and the
 * figures then say that the set is exactly what the configured bounds reach.
 */
export function intakeGuardRefusal(
  guard: ReceiptIntakeGuard,
  held: RetainedWindow,
  retainedBySuspension = 0,
): IntakeGuardFigures | null {
  if (guard.growPastGuard === true) return null;
  const periodSeconds = guard.retention?.maxAgeSeconds;
  const bound = guard.retention?.maxCount;
  if (periodSeconds === undefined || bound === undefined) return null;
  const fraction = guard.refusesAtFraction ?? DEFAULT_INTAKE_GUARD_FRACTION;
  // A threshold is read as a fraction of the bound, so it is never above the bound: a value over 1
  // would ask the guard to start reading after the store has run past the count that retires it,
  // which no state reaches, and a value that is not a positive finite number reads as the shipped
  // default rather than as a way to switch the guard off by typo. Turning it off is what
  // `growPastGuard` is for, and it is named and banners.
  const refusesAt =
    Number.isFinite(fraction) && fraction > 0 ? Math.min(bound, Math.ceil(fraction * bound)) : bound;
  if (held.count < refusesAt) return null;
  const source = guard.retention?.time ?? HOST_CLOCK_SOURCE;
  const needed = receiptsNeededForWindow(periodSeconds, held, source);
  if (needed === null || needed <= bound) return null;
  return {
    retained: held.count,
    refusesAt,
    bound,
    spanSeconds: held.to - held.from,
    spanSupportSeconds: measurableSpanSeconds(held, source),
    source: source.name,
    uncertaintySeconds: source.uncertaintySeconds,
    periodSeconds,
    needed,
    retainedBySuspension,
  };
}

/**
 * The detail carried by `RECEIPT_WINDOW_UNHOLDABLE`. It states the two configured quantities, how much
 * of the retained set a suspension rather than those quantities keeps, the measured span, the span the
 * source of those stamps supports, the count that span takes and the shortfall, in the order an operator
 * needs to raise a number from: the same discipline the opening refusal follows in `store.ts`, so a
 * refusal read off either moment tells the reader which bound is short, by how much, under which source
 * the answer was derived, and whether traffic or an instruction grew the set.
 */
function intakeGuardDetail(figures: IntakeGuardFigures): string {
  return (
    `the store holds ${figures.retained} of the ${figures.bound} receipts its durability bound allows, ` +
    // The two keepings are told apart because the fixes differ: a bound an operator set too low is
    // raised, and a set an instruction grew is answered by that instruction or by a wider bound, never
    // by a wait. Zero says the sentence belongs to the first of those.
    `${figures.retainedBySuspension} of them kept by a suspension the store was handed rather than by ` +
    `the bounds it was configured with, refusing from ${figures.refusesAt} of them, those stamps span ` +
    `${figures.spanSeconds} seconds as read from ${sourcePhrase(figures)}, which is ` +
    `${figures.spanSupportSeconds} seconds a rate can be ` +
    `derived from, while ` +
    `the configured period is ${figures.periodSeconds} seconds, and that period takes ${figures.needed} ` +
    `receipts at the rate this store has been carrying, which is ${figures.needed - figures.bound} more ` +
    `than the bound holds. Issuing this completion would retire a receipt the period still covers, so it ` +
    `is refused before any inference is run. Raise the durability bound to at least ${figures.needed}, ` +
    `shorten the period beside it, or let the traffic this store carries fall; reads, verification and ` +
    `handover are served from the receipts already filed and are unaffected`
  );
}

/** The source and its bound, spelled the way a refusal has to spell it: measured, or not. */
function sourcePhrase(figures: IntakeGuardFigures): string {
  return sourceSentence({ name: figures.source, uncertaintySeconds: figures.uncertaintySeconds });
}

/**
 * The completion bound, stated in the two fields a credential's own `rate` and `--peer-rate` carry, so an
 * operator can set it against the per-address bound it has to sit under. It is worked from one measured
 * number rather than from two costs added together: this gateway, driven over HTTP with a file store behind
 * it and both other buckets lifted, turned over 837 completions a second with 32 callers in flight, sixteen
 * callers hold the same rate, and past them the throughput is flat and only the wait grows. The fastest of
 * those runs is the ceiling, so 837 a second becomes 50,220 a minute and the burst is one second of the same
 * figure. Against the 6,000 a minute one connection address is held to, that is 8.4 busy addresses filling
 * one process, which is why the bound is refused rather than documented. No value here removes the bound: a
 * number no deployment reaches is
 * the off switch, and the start-up report prints whichever number the process is holding. A bound an operator
 * declares above what every credential in front of this process could spend is refused at start, because a
 * number that can never fire is not a bound; the rule sits in `cli.ts` beside the flag.
 *
 * The harness is part of the number: one Windows host, one Node 26 process, a mock upstream that answers at
 * once so the figure is this software's own cost rather than a model's, 2,000 buffered completions at each of
 * one, four, sixteen and thirty-two callers, the store's shipped durability bound, and the per-address and
 * credential rates widened so neither is what the run measures. It is a completion path measured end to end,
 * which is why it sits under the store's own append rate: an append is only one of the costs a request pays.
 *
 * That check answers from the runtime's own primitive under the refusals `strict-ed25519.ts` states, and the
 * bound moved with it once: the same harness on the same host, run back to back on Node 24 against the build
 * where the JavaScript reader answered, measured 432 completions a second at 32 callers at 2.62 ms of process
 * CPU per completion, where the primitive build measured 1,168 at 1.45 ms. Four callers used to be the plateau
 * because a synchronous 1.5 ms check serialises the event loop, and 105 microseconds does not. Until that run
 * the default carried 322 a second, so a deployment sized against 19,320 a minute was refusing traffic the
 * primitive build could in fact carry.
 *
 * The awaited write the answer settles on moved again, and the bound follows it: the completion path now ends
 * at an access journal commit rather than at the dated part's own append, and the same harness on the same
 * host and day measures 837 a second at 32 callers at 2.3 ms of process CPU per completion, against 883 for
 * the build that awaited the dated part's append and 1,023 for the build that awaited nothing. The bound
 * names what one process serves end to end, and `--completion-rate` is still how an operator sizes the bound
 * against the box the deployment runs on rather than against a build that is not theirs.
 */
export const DEFAULT_COMPLETION_RATE: CredentialRate = { perMinute: 50_220, burst: 837 };

/**
 * The one key the deployment's bucket is held under. A counter with no key would be a counter per caller,
 * and the whole of this bound is that everyone shares one.
 */
const COMPLETION_BOUND_KEY = 'deployment';

/**
 * The deployment-wide bound on the completions one process admits.
 */
export interface DeploymentCompletionBound {
  /**
   * What this process admits, per minute and at once, in `DEFAULT_COMPLETION_RATE`'s two fields. Absent
   * means that constant, the ceiling this build measures on its own completion path rather than a round
   * number chosen for a banner, and there is no spelling here that turns the bound off.
   */
  readonly rate?: CredentialRate;
  /**
   * Milliseconds since the epoch, the one clock this bucket refills against. Absent means the host's own,
   * because a source reading whole seconds would price every request inside one second at no elapsed time
   * and refuse a burst the bound does not state. Injectable for the same reason the store's is: a case about
   * a refill cannot wait for real seconds to pass.
   */
  readonly nowMillis?: () => number;
}

/**
 * The detail carried by `DEPLOYMENT_RATE_LIMITED`: the quantity, the value it is configured at, and the
 * wait to the next token, because a refusal that named none of the three would read as a wall rather than
 * as a number an operator moves.
 */
function completionBoundDetail(rate: CredentialRate, retryAfterSeconds: number): string {
  return (
    `this gateway admits ${String(rate.perMinute)} completions a minute across the whole deployment and ` +
    `${String(rate.burst)} of them at once, and this completion is the one past that bound, so it is refused ` +
    `before any inference is run and no receipt is issued for it. The bound is a fact about this process and ` +
    `not about a credential, so no other credential and no different address clears it, a token appears in ` +
    `${String(retryAfterSeconds)} seconds, and an operator raises it with --completion-rate. Reads, ` +
    `verification and handover keep serving, because none of them issues a receipt`
  );
}

/**
 * The detail carried by `BODY_TOO_LARGE`: the bound this process reads, where a deployment states it, the
 * number a run that stated nothing reads, and what the refusal left undone. A 413 that named no figure would
 * send a caller back with slightly fewer bytes and no way to tell which number moved, which is the reading
 * this code exists to make impossible.
 */
function requestBodyLimitDetail(limitBytes: number): string {
  return (
    `this gateway reads no request body past ${String(limitBytes)} bytes, and this one was refused while that ` +
    `bound was being applied, before the route ran: nothing was sent to the upstream, no inference was paid ` +
    `for and no receipt was issued. The bound is a setting of this process, stated by ` +
    `ASHAVERI_REQUEST_BODY_LIMIT_BYTES or by the requestBodyLimitBytes option of buildGateway, and ` +
    `${String(DEFAULT_REQUEST_BODY_LIMIT_BYTES)} bytes is what a run that stated neither reads. A caller ` +
    `sends fewer bytes than the bound states, or asks whoever holds this deployment to state a larger one`
  );
}

/**
 * The detail carried by `RESIDENT_BODY_BUDGET_EXCEEDED`: the budget, how much of it is resident at the instant
 * the refusal was decided, what this request asked for, where the number comes from, and what a run that stated
 * nothing reads. Those four are the whole of what an operator needs to move a figure, and the two arms a refusal
 * is in have to be told apart in the sentence rather than left to the status, because one of them clears on a
 * wait and the other never does, and a caller that retried the second one forever would be doing exactly what
 * this answer exists to stop.
 *
 * The wait is a floor and the message says so. Nothing here can know when the bytes in flight are given back:
 * that is other requests finishing, not a refill, and the honest alternative to a stated floor is the
 * durability guard's silence, which this is not, because an empty process does hold these bytes.
 */
function requestBodyBudgetDetail(budget: ResidentBodyBudget, reservation: ResidentBodyReservation): string {
  const held = budget.residentBytes;
  const shared =
    `this gateway holds no more than ${String(budget.limitBytes)} bytes of request bodies at once, ` +
    `${String(held)} of them are resident now, and this request's ${String(reservation.bytes)} bytes do not fit ` +
    `beside them, so it is refused at the reader before the route ran: nothing was sent to the upstream, no ` +
    `inference was paid for and no receipt was issued. The budget is a setting of this process, stated by ` +
    `ASHAVERI_REQUEST_BODY_BUDGET_BYTES or by the requestBodyBudgetBytes option of buildGateway, and ` +
    `${String(DEFAULT_REQUEST_BODY_BUDGET_BYTES)} bytes is what a run that stated neither reads. `;
  if (reservation.retryAfterSeconds === undefined) {
    return (
      shared +
      `These bytes are past the whole budget on their own, so they would not be held by an empty process either ` +
      `and no wait clears this refusal: a caller sends fewer bytes, and an operator states a budget that covers ` +
      `the body bound this gateway reads, since a bound above the budget is a size this process refuses at any ` +
      `traffic. The size bound itself was not passed over: this body is inside it, and it is the sum of what is ` +
      `resident that decided this answer`
    );
  }
  return (
    shared +
    `These bytes are inside the size bound this gateway reads, so nothing about this request is wrong and the ` +
    `answer is a wait of ${String(reservation.retryAfterSeconds)} seconds, which is a floor rather than a ` +
    `measurement: the budget frees bytes when the requests holding them finish, and this process cannot see when ` +
    `that is. A caller waits and sends a new request; an operator moves the budget beside the memory this ` +
    `deployment has, and reads which of the two numbers it should be from the size bound above it`
  );
}

export function buildGateway(options: GatewayOptions): GatewayInstance {
  const { access, accessLog } = options;
  // The record stamp of this process: whole Unix seconds off the one source it was given, or off the
  // host clock when it was given none. `issue` below stamps the signed payload and the store's chain key
  // from the same reading, and the store retirement clock reads the very same source object, so a span
  // this file derives from its own stamps and a span an operator is quoted are the one number.
  //
  // Read ahead of the two lines below that build a guest and a backend, because a deployment this
  // function builds has to be built with it: evidence collected off one clock and filed against another
  // puts two instants that never met inside one signed payload, as `att.ts` beside `iat`.
  //
  // That is a promise about this wiring rather than about the option shapes. A caller can build
  // `dstackDeployment({ time: A })` outside this repository and hand the result to
  // `buildGateway({ deployment, time: B })`, and the two stamps are read off two clocks again with
  // nothing in the types refusing it; what closes that gap is whoever starts the process naming one
  // source once, which is what `gateway/src/cli.ts` does for every builder it calls.
  const time = options.time ?? HOST_CLOCK_SOURCE;
  const stamp = (): number => Math.floor(time.nowSeconds());
  // The access record's `t` is epoch milliseconds and a source reads whole seconds, so the line's stamp
  // is the same reading scaled once, which is the one reconciliation `aclog.ts` applies to the clock its
  // retention cutoff is drawn from. A line and the bound that ages it therefore answer to one source at
  // one resolution, and `t` resolves nothing finer than a second: two requests inside one second carry
  // the same `t` and are told apart by their `rid`, exactly as the day name drawn from it cannot split
  // them across two days. The duration beside it is an elapsed time inside this process and stays a
  // pair of host millisecond readings, because a one-second clock would price every fast request at zero.
  const stampMillis = (): number => stamp() * 1000;
  const deployment =
    options.deployment ??
    mockDeployment({ issuer: options.issuer, instance: options.instance, key: options.key, time });
  const backend = options.backend ?? mockBackend({ time });
  // Read once, where every other operator switch on this process is read: a completion is marked the
  // same way whichever route served it, and the value is reported on the start-up banner.
  const markingScheme = options.marking ?? DEFAULT_MARKING;
  // A store handed over by a deployment brings its own source, because the retention it was configured
  // with is that deployment's decision. The in-process default has no bounds at all, so the only thing its
  // clock can be asked is which instant a retirement is written under, and that reads the same source as
  // the receipts it would be timing.
  const receipts = options.store ?? openMemoryReceiptStore({ retention: { time } });
  // The durability policy this deployment configured, read once like every other switch on this
  // process. An absent guard is no guard: see `ReceiptIntakeGuard`.
  const intakeGuard = options.receiptIntakeGuard ?? {};
  // The deployment's own admission bound, read once the same way, and one counter behind it for the whole
  // process: the bound is what one gateway can write, so it is held on nothing narrower than the process
  // that writes it and on nothing wider than the counter a process can keep.
  const completionBound = options.completionBound ?? {};
  const completionRate = completionBound.rate ?? DEFAULT_COMPLETION_RATE;
  const completionTokens = new TokenBucket();
  const completionMillis = completionBound.nowMillis ?? (() => Date.now());
  // The cache an issuance reads its anchor from, read once like every other switch on this process.
  // Absent is a state with its own answer rather than a default to fill in: an unwired gateway signs the
  // anchor of a collector that took nothing in, and says so in the words that name the collector.
  const appraisal = options.appraisal;
  // One HKDF over the deployment's own signing seed, for the whole process. The id a receipt is
  // fetched by is minted here rather than taken from the upstream, and nothing is written down to
  // make the fetch work: the id carries the tag of the credential that minted it.
  const receiptIds = new ReceiptNamespace(deployment.key);

  // The request body bound, read once like every other switch on this process, and read before the
  // instance is built because it is the first thing the process does with a caller's bytes.
  const requestBodyLimitBytes =
    options.requestBodyLimitBytes ?? requestBodyLimitFromEnvironment() ?? DEFAULT_REQUEST_BODY_LIMIT_BYTES;
  if (!Number.isInteger(requestBodyLimitBytes) || requestBodyLimitBytes < 1) {
    throw new RangeError(
      `requestBodyLimitBytes is ${String(requestBodyLimitBytes)}, and a request body bound is a positive whole number of bytes`,
    );
  }

  // The resident request-body budget, read the same three ways and validated the same way, and held on this
  // process for the same reason the completion counter is: what is resident is a fact about one process's
  // memory, so the bound on it is kept on nothing narrower than the process that holds it and on nothing wider
  // than the counter one process can keep. It is read here, beside the bound above it and not behind the routes,
  // because a budget that is consulted after the bytes arrived cannot bound their arrival, which is what it is
  // for. See section 1 of `docs/access-control.md` for the placement and the reason it is lawful.
  const requestBodyBudgetBytes =
    options.requestBodyBudgetBytes ?? requestBodyBudgetFromEnvironment() ?? DEFAULT_REQUEST_BODY_BUDGET_BYTES;
  const residentBodies = new ResidentBodyBudget(requestBodyBudgetBytes);

  const app = Fastify({ bodyLimit: requestBodyLimitBytes, logger: false });
  // The receipt binds the exact bytes the client sent, so the body is kept raw
  // instead of being parsed into a JS object first.
  //
  // This is also where those bytes are charged to the budget, and the charging is done as they arrive
  // rather than once they have all arrived. Two reasons, one about the number and one about what a
  // number bounds:
  //
  // - What the charge is, is what this process actually took in, not what the caller declared. A
  //   declared `Content-Length` is a caller's claim, and three of them are false in ways this process
  //   would pay for: a body that arrives with no length at all, under `Transfer-Encoding: chunked`, is
  //   as large as whoever sent it decides while it is sent; a length that disagrees with the bytes is
  //   refused by the HTTP parser before any chunk reaches this line, so nothing here can be charged by
  //   it; and the reader's own bound is applied to the bytes it accumulated rather than to the header.
  //   Charging the header would let a caller reserve one byte and hold a hundred and twenty-eight
  //   megabytes, which is a budget that bounds nothing.
  // - A charge taken after the body is complete bounds how long the bytes are held and never whether
  //   they may arrive, and the second of those is the whole point of the number. Measured on the
  //   platform deployments run on, at 128 MiB bodies and sixteen callers in flight with a 512 MiB
  //   budget, the process that charged the completed body peaked at 3,028.0 MiB where the same tree
  //   with no budget at all peaked at 4,094.8 MiB: the refusals were decided, the arithmetic held, and
  //   the memory was still paid for by the callers that were turned away, because their bytes had all
  //   arrived before any of them was refused. The same load with the charge taken chunk by chunk peaked
  //   at 1,035.3 MiB, and that ceiling sat at 2.05 times the budget at every body width and every
  //   concurrency in two independent runs. Runtime for all three figures: `v26.13.1` inside
  //   `node:26-slim`, which is the deployment platform and not this host's `v26.13.0`.
  //
  // So the question is asked at the chunk that carries the sum past the budget, which is the earliest
  // moment this process can honestly ask it: nothing is reserved against a caller's word, and no byte
  // is charged twice. What the overshoot therefore is, is one chunk of the refused request rather than
  // one whole body of it, and it is bounded by the width a chunk arrives at, not by
  // `requestBodyLimitBytes` beside it.
  app.addHook('preParsing', (request, _reply, payload, done) => {
    // A bodyless method has no arrival to bound, and wrapping its payload would put a reader between a
    // stream nothing downstream consumes and the socket: `handleRequest` goes straight to the route for
    // these two methods, so the wrapper's readable side would never be drained and the request would
    // stall on that backpressure rather than on any decision this process made.
    if (request.method === 'GET' || request.method === 'HEAD') {
      done(null, payload);
      return;
    }
    const state = stateOf(request);
    let charged = 0;
    const arrival = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        const reservation = residentBodies.reserve(chunk.length);
        if (!reservation.admitted) {
          // The bytes of this request that did get through are this request's to give back, and the
          // release site already reads the figure off the request's own state, so a refusal partway
          // through an upload unwinds exactly the part it charged. This line is the whole of the undo,
          // and it is the shape 1 refusal's `nothing was charged` arm turned into a number: the
          // crossing chunk itself was refused, so it joins no sum.
          if (state !== undefined) state.residentBytes = charged;
          callback(
            new AccessError('RESIDENT_BODY_BUDGET_EXCEEDED', {
              detail: requestBodyBudgetDetail(residentBodies, reservation),
              retryAfterSeconds: reservation.retryAfterSeconds,
            }),
          );
          return;
        }
        charged += chunk.length;
        if (state !== undefined) {
          // Cumulative rather than per chunk, so the release has exactly one number to give back and can
          // be asked for twice without moving it twice. That is the same rule the charge ran on when it
          // sat in the parser below, and it is what keeps a mid-read refusal and a served completion
          // releasing through the one site.
          state.residentBytes = charged;
        }
        callback(null, chunk);
      },
    });
    payload.pipe(arrival);
    done(null, arrival);
  });

  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_request, body, done) => {
    // The bytes still travel raw, which is what the receipt signs. What moved out of here is the
    // charge, and it moved to the arrival counter above: this callback is handed the whole body after
    // the reader finished accumulating it, so a sum taken here can only be a statement about what is
    // already held. A charge left here as well would bill every body twice.
    done(null, body);
  });

  // Two refusals are decided at the reader rather than by a route, and both are answered here because neither
  // can be answered anywhere else: by the time a route runs, the bytes are held and the sum is spent. The first
  // arrives as the framework's own word for a body past the bound it was handed, and that word is a shape of
  // nothing on this route, `{statusCode, error, code, message}`, while every other refusal these routes give is
  // `{error:{message,type}}`. A caller branching on `error.type` would meet a refusal it could not name, so the
  // framework's answer is rewritten here in the route's shape, with a code of its own and the bound in its
  // sentence. Both of the two shapes a body arrives in reach that one answer: a declared `Content-Length` past
  // the bound is refused before a byte is read, and a body that grows past it while being read is refused at the
  // chunk that passes it.
  //
  // The second arrives as this file's own `AccessError`, from the charge above, and it keeps the shape the
  // admission refusals give rather than the shape the size refusals give, which is the difference a caller acts
  // on: `BODY_TOO_LARGE` says these bytes are wrong, and `RESIDENT_BODY_BUDGET_EXCEEDED` says these bytes are
  // right and this moment is full. `authentication_error` is the type every refusal on this route that carries a
  // `retry-after` already answers with, from the credential bucket and the connection's bound through the
  // durability guard and the completion counter, and the code is what names which of them this is. It is not
  // `invalid_request_error`, which would tell a caller to change a request that needed no changing, and no new
  // type word is coined for one more refusal, because a caller that branches on `type` today would meet a literal
  // it has never seen. `error.code` and the status are where this answer is distinguishable, and both are pinned.
  //
  // Anything else is handed back to the handler this one replaced, because this file writes no answer for a
  // refusal it did not decide: a media type it does not parse, a body that disagrees with its own length, a
  // credential file that failed to reload, and a fault from inside a route keep the answer the reader gives
  // them. That last set is why this branch is keyed on the code rather than on `AccessError` at large, which is
  // what a reload failure is, and why the two arms below build their envelopes separately.
  app.setErrorHandler((error: FastifyError, _request, reply) => {
    if (error.code === 'RESIDENT_BODY_BUDGET_EXCEEDED' && error instanceof AccessError) {
      const wait = error.retryAfterSeconds === undefined ? reply : reply.header('retry-after', String(error.retryAfterSeconds));
      return wait
        .code(error.status)
        .send({ error: { message: error.message, type: 'authentication_error', code: error.code } });
    }
    if (error.code !== 'FST_ERR_CTP_BODY_TOO_LARGE') {
      return reply.send(error);
    }
    const refusal = new AccessError('BODY_TOO_LARGE', { detail: requestBodyLimitDetail(requestBodyLimitBytes) });
    return reply
      .code(refusal.status)
      .send({ error: { message: refusal.message, type: 'invalid_request_error', code: refusal.code } });
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
    /** The request's arrival as this process's named source reads it, in epoch milliseconds: `t`. */
    arrivedAt: number;
    /** The host millisecond the request began, which the duration alone is measured from. */
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
    logging?: Promise<void>;
    /**
     * The request-body bytes this request holds on the process's budget, and zero once they have been given
     * back. The charge is written by the reader and cleared by the release below, and holding the figure here
     * rather than only in the budget is what makes the release exactly-once by construction: a second call sees
     * zero and gives nothing back, so the arithmetic cannot be moved twice by the two events a response's death
     * is announced with.
     */
    residentBytes: number;
  }

  const states = new WeakMap<FastifyRequest, RequestState>();

  function stateOf(request: FastifyRequest): RequestState | undefined {
    return states.get(request);
  }

  /**
   * Give back whatever this request still holds of the budget, if it holds anything.
   *
   * One site, because the defect class this is written against is a leak: a charge released on the paths a
   * reviewer thought of and not on the others leaves the resident figure higher than the process is holding,
   * every request adds to it, and the deployment reaches a state where a budget refuses everything while the
   * traffic looks merely heavy. So the release is attached to the two events a response's death is announced
   * with, the same pair the access line is flushed on for the same reason, and the request's own charge is
   * cleared as it is handed back, which makes the second call give nothing.
   *
   * Both events are needed and neither covers the other. `finish` says this process wrote a whole answer, which
   * is every completion, every refusal after the charge, and every upstream failure; `close` says the connection
   * is done with, which is a client that went away mid-request, a stream that ended early, and a reply that was
   * hijacked past `onSend`. A request that was never charged reaches this and gives back zero.
   */
  function releaseResidentBytes(request: FastifyRequest): void {
    const state = stateOf(request);
    if (state === undefined || state.residentBytes === 0) return;
    const bytes = state.residentBytes;
    state.residentBytes = 0;
    residentBodies.release(bytes);
  }

  async function flush(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const state = stateOf(request);
    if (state === undefined) return;
    if (state.logging !== undefined) return state.logging;
    const record: AccessRecord = {
      t: state.arrivedAt,
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
    // Retain one shared attempt even if the writer throws or rejects.
    state.logging = Promise.resolve().then(() => accessLog.record(record)).catch(() => {
      // The disabled HTTP logger cannot report this; keep the process warning payload-free.
      process.emitWarning('The access log refused a record; the response will continue without retry.', {
        code: 'ASHAVERI_ACCESS_LOG_WRITE_FAILED',
      });
    });
    return state.logging;
  }

  app.addHook('onRequest', async (request, reply) => {
    states.set(request, {
      // Two readings, on purpose: the arrival the line reports and the base the duration is measured
      // from. The first is this process's named source, so the stamp a retention bound ages is the same
      // clock that bound is drawn from; the second is the host's, and reaches nothing but `dur`.
      arrivedAt: stampMillis(),
      startedAt: Date.now(),
      rid: randomUUID(),
      credential: null,
      tag: null,
      auth: null,
      scope: null,
      nonce: null,
      receiptId: null,
      deny: null,
      residentBytes: 0,
    });
    // Hijacked replies bypass onSend, so close and finish join the shared append. The same two events end a
    // request's hold on the budget, and the release goes first: a writer that throws or rejects has to leave
    // this process's arithmetic settled, and the line it failed to write is reported by the warning below.
    reply.raw.once('finish', () => {
      releaseResidentBytes(request);
      flush(request, reply).catch(() => undefined);
    });
    reply.raw.once('close', () => {
      releaseResidentBytes(request);
      flush(request, reply).catch(() => undefined);
    });
  });

  // Await sends so handler resolution cannot restart the lifecycle while onSend awaits the append.
  app.addHook('onSend', async (request, reply) => {
    await flush(request, reply);
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
      // The durability guard, and the sixth check this pipeline makes. It sits behind all five of
      // `CredentialStore.admit` for the reason section 1 of `docs/access-control.md` states as a rule:
      // a check that reads the credential file answers only to a caller that proved a key, and a check
      // that reads nothing a caller wrote answers alike to everyone who got that far. This one reads the
      // retained set and the two configured numbers, so it names no credential, distinguishes no
      // credential id, and varies with nothing in the file. It sits ahead of every route body, and so
      // ahead of `backend.respond`, because what it declines is the issuance of a receipt rather than
      // the computation behind one: an inference already run is an inference paid for, and a completion
      // answered without a receipt is the recording obligation dropped rather than a capacity
      // preference. Only a route that issues one is read at all, which is what keeps verification,
      // receipts already filed, and handover serving while intake refuses.
      //
      // The store reports its retained set asynchronously, so the wait is here and nothing has been
      // written about the admission yet: a refusal leaves `cred` to the error's own field below, and
      // `auth` and `scope` null, because what the refusal says did not happen is the issuing of a
      // receipt and not the verifying of a key.
      if (admitted.scope === 'complete') {
        // The suspension count travels with the window, because one sentence answers two different
        // deployments and an operator reading a shortfall needs to know whether the bound or an
        // instruction handed to the store is what grew the set beside it. A store handed no suspension
        // answers it without a walk, so the read costs nothing where there is nothing to report.
        const refusal = intakeGuardRefusal(
          intakeGuard,
          await receipts.window(),
          await receipts.retainedBySuspension(),
        );
        if (refusal !== null) {
          throw new AccessError('RECEIPT_WINDOW_UNHOLDABLE', {
            detail: intakeGuardDetail(refusal),
            credentialId: admitted.credentialId ?? undefined,
          });
        }
        // The deployment-wide bound, and the seventh check on a completion. It sits behind the guard for
        // the same arithmetic's reason: a token spent on a completion the store could not have kept is a
        // token spent on a receipt nothing was filed for, and this bound states what this process issues,
        // so it counts only what reaches it. One counter, keyed on the process rather than on a caller, so
        // it names no credential and varies with nothing in the file, which is what makes a place behind
        // the five lawful for it on the rule section 1 of `docs/access-control.md` states. It is ahead of
        // every route body, and so of `backend.respond`, because what it declines is the writing of a
        // receipt: past this line an inference is paid for and no bytes arrive for it.
        const taken = completionTokens.take(COMPLETION_BOUND_KEY, completionRate, completionMillis());
        if (!taken.allowed) {
          throw new AccessError('DEPLOYMENT_RATE_LIMITED', {
            detail: completionBoundDetail(completionRate, taken.retryAfterSeconds),
            retryAfterSeconds: taken.retryAfterSeconds,
            credentialId: admitted.credentialId ?? undefined,
          });
        }
      }
      state.credential = admitted.credentialId;
      // Held on the request the moment admission names the credential, so a mint and a read compare
      // the same value they were admitted with rather than looking one up again per request. A public
      // route names no credential, and no route that mints or reads a receipt is public, so null here
      // reaches only a body that asks for no tag.
      state.tag = admitted.credentialId === null ? null : receiptIds.tagFor(admitted.credentialId);
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
      const refusal = err.retryAfterSeconds === undefined ? reply : reply.header('retry-after', String(err.retryAfterSeconds));
      await refusal.code(err.status).send({ error: { message: err.message, type: 'authentication_error', code: err.code } });
      return;
    }
  });

  // The document this deployment publishes about its own keys, in one of the two shapes a deployment can be
  // in. With a journal beside its store, the history in that journal is the document's `keys[]`: every epoch
  // this deployment has signed under, the key it held then, and the instant it began accepting signatures
  // from that key. Without one, the manifest carries the single key this process stands on and states no
  // window at all, which is what every deployment before the journal served and what a reader answers as
  // "this document declares no epochs" rather than as a key that has always been the key.
  //
  // A history is published only where a reader can weigh it. Two entries say something about a key that is
  // no longer in use, and an unsigned document saying that is a claim any observer between this process and
  // its clients could have written, so a journal naming more than one epoch behind an unsigned manifest stops
  // the run. One entry claims nothing beyond the key the document already carries and stays plain JSON.
  const journal = options.epochJournal;
  if (journal !== undefined) {
    const unsealed = unsealedHistoryRefusal(journal, deployment.manifestKey !== undefined);
    if (unsealed !== null) throw new EpochJournalError(unsealed);
  }
  const manifest: ManifestJson = {
    v: 1,
    iss: deployment.issuer,
    ins: deployment.instance,
    epk: deployment.epk,
    keys:
      journal === undefined
        ? [{ kid: toHex(deployment.key.kid), alg: 'Ed25519', publicKey: toBase64Url(deployment.key.publicKey) }]
        : journal.entries.map((entry: EpochJournalEntry) => ({
            kid: entry.kid,
            alg: 'Ed25519',
            publicKey: entry.publicKey,
            epk: entry.epk,
            validFrom: entry.validFrom,
          })),
    models: deployment.models.map((model) => ({ id: model.id, wts: toHex(model.wts) })),
    meas: { tee: deployment.tee, m: toHex(deployment.measurement) },
  };

  /**
   * The anchor of one issuance, read out of the cache its deployment wired.
   *
   * A gateway wired with no reader answers the `no-cache` arm, which is `notTakenInAnchor` and nothing
   * else, so an unwired deployment signs the anchor of a collector that took nothing in and consults no
   * cache. A reader is awaited because a cache a deployment wires sits on disk, and it is caught because a
   * cache that fails is a fact about the cache and not about the response: the completion is served, the
   * receipt is signed, and both slots state the failed read rather than carrying a word of it into a
   * document a reviewer cites. The message goes to the log beside the request that met it, which is where
   * a stack belongs.
   */
  async function anchorForEvidence(evidence: AttestationBundle): Promise<CollateralValidityAnchor> {
    if (appraisal === undefined) return anchorFrom({ state: 'no-cache' });
    try {
      return anchorFrom(await appraisal(evidence));
    } catch (err) {
      app.log.error({ err }, 'the wired appraisal reader failed, and the anchor states the failed read');
      return readFailedAnchor();
    }
  }

  async function issue(args: {
    id: string;
    identity: PayloadIdentity;
    responseHash: Uint8Array;
    framing: FramedItemStamps;
    modelId: string;
    weights: Uint8Array;
    evidence: AttestationBundle;
    usage: CompletionUsage;
    marking: Marking;
  }): Promise<void> {
    const iat = stamp();
    // The instant this payload states bounds every item stamp it carries. Each frame passed before this
    // reading was taken, so under a source that does not step back the bound holds of itself; a source
    // that does can read this instant below the stamps the list already carries, because the clamp keeping
    // the list in its own order is a floor and not a ceiling. `boundStampsAt` reconciles the two at the
    // one place the payload's instant exists.
    const framing = boundStampsAt(args.framing, iat);
    // One version, and every member it names is filled from what this issuance actually holds. `mk` is
    // required, so the answer to "was this response marked?" is a value in a signed document rather than
    // the absence of one. `sd` is the source `iat` was read from, which every process has, and `cva` is
    // what became of the appraisal context of the evidence this payload digests: on a deployment that
    // wired no reader it is the two absences of a collector that took nothing in, and on one that wired a
    // cache it is the digests a scheduled appraisal observed, or the absence that appraisal's own instants
    // state. Both members are answered beside the payload rather than by a policy field beside this
    // gateway, because what a receipt states is not the same as what a reader agrees to accept. A verifier
    // weighing the anchor is the one that refuses `not-taken-in`, and that refusal is not this document's
    // to write.
    //
    // `itm` is the member with a demand this gateway cannot always meet: it is required and it is never
    // empty, because a run of nothing states nothing and `readItemStamps` refuses one on bytes that are
    // otherwise well-formed. `ResponseItemFramer` answers `framed: false` for a response that said nothing
    // in any `data:` frame, and there is no shorter document left to fall back to: a receipt over those
    // bytes would have to be a document this package's own reader rejects. So the issuance stops there,
    // which is the second ending `gateway/src/item-stamps.ts` states for a response whose items this
    // gateway cannot state, and it says it by destroying the body rather than terminating it. The destroy
    // takes the response head with it: measured on a loopback socket, the client's read returns nothing at
    // all, so no id reaches anyone and the completion is simply not served. Minting one records nothing,
    // because only issuance writes a document. One version says everything, so it says nothing about a
    // response that has nothing to be said, and the whole cost of that is one completion per stream that
    // framed no item.
    if (!framing.framed) {
      throw new Error(`no item list to attest: ${framing.why}`);
    }
    // Read after that refusal rather than before it: a response this gateway can state nothing about earns
    // no read of anything else, so an unframed stream never touches a deployment's cache.
    const cva = await anchorForEvidence(args.evidence);
    const payload: ReceiptPayload = {
      ...args.identity,
      iss: deployment.issuer,
      ins: deployment.instance,
      iat,
      res: args.responseHash,
      mdl: args.modelId,
      wts: args.weights,
      meas: { tee: deployment.tee, m: deployment.measurement },
      att: { d: sha256(args.evidence.document), ts: args.evidence.timestamp, url: args.evidence.url },
      epk: deployment.epk,
      tok: meteringOf(args.usage),
      mk: args.marking,
      sd: stampDisclosureOf(time),
      cva,
      itm: framing.stamps,
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
  // no such key the route serves the plain document, which is not a failure and is not
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
    await reply.header('content-type', 'application/cose').send(Buffer.from(sealedManifest));
  });

  // The bytes a receipt's `wts` names, addressable by that digest. The manifest is read once at start-up
  // and the one reading is held on the deployment, so a request never touches the file: what this route
  // serves is what every receipt of the run states, even after the file on disk changes. The body is the
  // file's own bytes rather than a rendering of the parsed document, because the client's check is that
  // sha256(body) equals the path digest its receipt carries. A digest this deployment does not hold and a
  // deployment that holds none answer alike, so a caller learns only that these bytes are not here.
  app.get('/v1/weights/:digest', async (request, reply) => {
    const digest = (request.params as { digest: string }).digest;
    if (!WEIGHTS_DIGEST_HEX.test(digest)) {
      await reply.code(400).send({
        error: { message: 'digest must be 64 lowercase hex characters', type: 'invalid_request_error' },
      });
      return;
    }
    const weightsManifest = deployment.weightsManifest;
    if (weightsManifest === undefined || toHex(weightsManifest.digest) !== digest) {
      await reply.code(404).send({ error: { message: `no weights manifest for digest ${digest}`, type: 'not_found' } });
      return;
    }
    await reply.header('content-type', 'application/json').send(Buffer.from(weightsManifest.bytes));
  });

  app.get('/v1/attestation', async (request, reply) => {
    const query = request.query as { report_data?: string };
    let reportData: Uint8Array | null = null;
    if (query.report_data !== undefined) {
      if (!REPORT_DATA_HEX.test(query.report_data)) {
        await reply
          .code(400)
          .send({ error: { message: 'report_data must be 64 hex characters', type: 'invalid_request_error' } });
        return;
      }
      reportData = fromHex(query.report_data);
    }
    const bundle = await deployment.attestation(reportData);
    await reply.header('content-type', 'application/octet-stream').send(Buffer.from(bundle.document));
  });

  // The device leg has no standing answer to fall back on: an accelerator document is
  // only worth fetching if it names the challenge of the receipt being checked.
  app.get('/v1/attestation/gpu', async (request, reply) => {
    if (deployment.deviceAttestation === undefined) {
      await reply.code(404).send({ error: { message: 'this deployment makes no device claim', type: 'not_found' } });
      return;
    }
    const query = request.query as { report_data?: string };
    if (query.report_data === undefined || !REPORT_DATA_HEX.test(query.report_data)) {
      await reply.code(400).send({
        error: { message: 'report_data must be 64 hex characters', type: 'invalid_request_error' },
      });
      return;
    }
    const device = await deployment.deviceAttestation(fromHex(query.report_data));
    await reply.header('content-type', 'application/octet-stream').send(Buffer.from(device.document));
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
      await reply.code(404).send({ error: { message: `no receipt for id ${id}`, type: 'not_found' } });
      return;
    }
    await reply.header('content-type', 'application/cbor').send(Buffer.from(bytes));
  });

  app.post('/v1/chat/completions', async (request, reply) => {
    if (!(request.body instanceof Buffer)) {
      await reply.code(400).send({ error: { message: 'request body must be application/json', type: 'invalid_request_error' } });
      return;
    }
    const raw = request.body;
    // Read off the bytes the client sent, and read shallowly: which model this request is for and whether
    // it asks for a stream are the only two things this route weighs, and a body whose bulk is one inline
    // file is not worth a string of itself and a graph of it held until the completion is over. The
    // grammar is still settled here, in full, so a shape this gateway has always refused is refused before
    // an inference is paid for, whichever backend the deployment runs.
    let head;
    try {
      head = readChatCompletionHead(raw);
    } catch (err) {
      const message = err instanceof RequestError ? err.message : 'request body is not valid JSON';
      await reply.code(400).send({ error: { message, type: 'invalid_request_error' } });
      return;
    }
    const declared = deployment.models.find((model) => model.id === head.model);
    if (declared === undefined) {
      await reply.code(400).send({
        error: { message: asOneLine(`model '${head.model}' is not served by this deployment`), type: 'invalid_request_error' },
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
        await reply.code(400).send({ error: { message: 'x-ashaveri-nonce is not valid base64url', type: 'invalid_request_error' } });
        return;
      }
      if (nonce.length !== NONCE_BYTES) {
        await reply.code(400).send({ error: { message: `x-ashaveri-nonce must be ${NONCE_BYTES} bytes`, type: 'invalid_request_error' } });
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
      await reply.code(500).send({
        error: {
          message: 'this request was admitted without a credential, so its receipt could not be addressed',
          type: 'server_error',
        },
      });
      return;
    }

    let response: BackendResponse;
    try {
      response = await backend.respond(raw, requestForBackend(raw, head));
    } catch (err) {
      await upstreamError(reply, `inference upstream failed: ${errorMessage(err)}`);
      return;
    }

    // The payload's own members are minted here, before the upstream is called, so the value the platform is
    // asked to seal is read out of the document this issuance signs instead of agreeing with it by accident,
    // and the evidence arrives while the model generates rather than after it.
    const identity = mintIdentity(nonce, raw);
    const evidencePromise = deployment.attestation(reportDataFor(identity));
    evidencePromise.catch(() => undefined);
    const failed = response.status >= 400;

    // The one question that decides which of the two arms below runs is `isEventStream`'s, and this route
    // asks it of the shipped reader rather than of a literal, because the same predicate is what tells
    // the item framing whether it is walking frames or holding one whole body. Two spellings of the test
    // would let a body be forwarded as a stream and attested as a single item, or the other way round,
    // and both readings would be internally consistent.
    if (failed || !isEventStream(response.contentType)) {
      // A buffered body can be hashed and signed before a single byte reaches
      // the client, so an unreceipted response is never observable.
      let body: Buffer;
      try {
        body = await collect(response, failed ? 'upstream-failure' : 'completion');
      } catch (err) {
        // The one answer this route refuses without signing it, and it is refused by this process rather than
        // by the inference server: the bound is `MAX_BUFFERED_BODY`, so what comes back carries the code a
        // caller can branch on and the number that moved. The match is on that code and not on the class it
        // belongs to, because every refusal this gateway raises belongs to that class, the credential checks'
        // own among them: an error raised while collecting that was not this bound would answer the caller
        // with the status of a check that never ran on this request, and every 5xx on that union is a
        // credential-file refusal no request is answered with. Anything else this loop raised is still the
        // upstream's own failure and keeps the untyped fault it has always been answered with.
        if (err instanceof AccessError && err.code === 'RESPONSE_TOO_LARGE') {
          await reply
            .code(err.status)
            .send({ error: { message: err.message, type: 'upstream_error', code: err.code } });
          return;
        }
        await upstreamError(reply, errorMessage(err));
        return;
      }
      const buffered = reply.header('content-type', response.contentType);
      if (failed) {
        await buffered.status(response.status).send(body);
        return;
      }
      let usage: CompletionUsage;
      try {
        usage = await response.usage;
      } catch (err) {
        await upstreamError(reply, errorMessage(err));
        return;
      }
      if (usage.model.length > 0 && usage.model !== declared.id) {
        await upstreamError(reply, `inference upstream served '${usage.model}' instead of '${declared.id}'`);
        return;
      }
      const receiptId = receiptIds.mint(receiptTag);
      // One body, one hash, one write: the marking member is inside the bytes before they are
      // digested, so there is no route by which a receipt is issued over a response that was never
      // marked, and none by which a client is sent bytes other than the ones it is vouched for.
      const marked =
        markingScheme === 'none'
          ? null
          : markBufferedBody(body, stamp());
      if (marked !== null && !marked.marked) {
        // The flag asked for a mark and this response's shape cannot carry one, which is a fact a
        // caller has to be told. Serving the body unmarked and signing `sch: none` would be true of
        // the bytes and false to the deployment's own configuration, and the reader who could act on
        // the difference is this one.
        await upstreamError(reply, marked.why);
        return;
      }
      const sent = marked === null ? body : Buffer.from(marked.body);
      // Framed out of the bytes about to be handed over, after the mark went in and before anything is
      // signed, which is the same span `res` digests and the same span `mk.d` cuts a region out of.
      const framing = stampedBufferedItem(stamp, response.contentType, sent);
      await issue({
        id: receiptId,
        identity,
        responseHash: sha256(sent),
        framing,
        modelId: declared.id,
        weights: declared.wts,
        evidence: await evidencePromise,
        usage,
        marking: marked === null ? unmarked() : marked.marking,
      });
      await buffered.header('x-ashaveri-receipt-id', receiptId).send(sent);
      return;
    }

    const iterator = response.chunks[Symbol.asyncIterator]();
    const early: Buffer[] = [];
    // Delay headers so a silent upstream gets a 502 rather than an empty receipted 200.
    try {
      while (early.length === 0) {
        const next = await withTimeout(iterator.next(), FIRST_EVENT_TIMEOUT_MS, 'inference upstream produced no response bytes');
        if (next.done === true) {
          break;
        }
        early.push(Buffer.from(next.value));
      }
    } catch (err) {
      await upstreamError(reply, errorMessage(err));
      return;
    }
    if (early.length === 0) {
      await upstreamError(reply, 'inference upstream produced an empty response body');
      return;
    }
    const id = receiptIds.mint(receiptTag);
    const hasher = createHash('sha256');
    // Receipt hashes and item stamps must cover the marked outgoing sequence.
    const items = new StreamedItemStamps(stamp);
    // Mark placement and completion gating have different boundaries.
    const tail = markingScheme === 'none' ? null : new AsyncMarkedStreamTail();
    const completion = new StreamCompletionGate();

    // Raw SSE avoids unreliable delivery through Fastify's generator-backed streams.
    const res = reply.hijack().raw;
    res.writeHead(response.status, {
      'content-type': response.contentType,
      'x-ashaveri-receipt-id': id,
      'cache-control': 'no-cache',
      // A stream this gateway declined to copy is a stream whose token figures were never asked for, and its
      // receipt says so itself: the pair it signs is two nulls, not two numbers nobody measured. This header is
      // the same statement made where a signed document cannot make it, before the body ends and while the
      // caller still has nothing to verify. What it cannot say is whether figures arrived, because the headers
      // are written before the body does.
      ...(response.meteringDeclined === true ? { 'x-ashaveri-metering': 'declined' } : {}),
    });
    // A property keeps callback state visible to the write loop's narrowing.
    const client = { aborted: false };
    const disposeCompletion = async (): Promise<void> => {
      const results = await Promise.allSettled([tail?.dispose(), completion.dispose()]);
      if (results.some((result) => result.status === 'rejected')) {
        res.destroy(new Error('Temporary response storage cleanup failed'));
      }
    };
    res.once('close', () => {
      client.aborted = true;
      disposeCompletion().catch(() => undefined);
    });

    // Both ordinary writes and the released terminal tail keep the socket's backpressure.
    const send = async (chunk: Uint8Array): Promise<void> => {
      if (chunk.length === 0 || client.aborted) return;
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

    // Account for gated bytes before issuance without releasing their completion signal.
    const write = async (chunk: Uint8Array): Promise<void> => {
      hasher.update(chunk);
      items.written(chunk);
      await completion.write(chunk, send);
    };

    // Mark placement must precede hashing and completion gating.
    const forward = async (chunk: Uint8Array): Promise<void> => {
      if (tail === null) {
        await write(chunk);
        return;
      }
      await tail.write(chunk, write);
    };

    let upstreamDone = false;
    try {
      for (const chunk of early) {
        await forward(chunk);
      }
      while (!client.aborted) {
        const next = await iterator.next();
        if (next.done === true) {
          upstreamDone = true;
          break;
        }
        await forward(next.value);
      }
      if (client.aborted) {
        return;
      }
      const usage = await response.usage;
      if (usage.model.length > 0 && usage.model !== declared.id) {
        res.destroy(new Error(`inference upstream served '${usage.model}' instead of '${declared.id}'`));
        return;
      }
      // The mark must pass through the same hash and framing path.
      let marking = unmarked();
      if (tail !== null) {
        const mark = markingFrame(declared.id, stamp());
        await tail.finishing(mark.frame, write);
        marking = mark.marking;
      }
      if (res.destroyed) return;
      // Sign the whole prepared sequence before its completion signal is observable.
      await issue({
        id,
        identity,
        responseHash: new Uint8Array(hasher.digest()),
        // Read after every outgoing frame is prepared, including the mark and terminal tail.
        framing: items.answer(),
        modelId: declared.id,
        weights: declared.wts,
        evidence: await evidencePromise,
        usage,
        marking,
      });
      await flush(request, reply);
      await completion.finishing(send);
    } catch (error) {
      res.destroy(error instanceof Error ? error : new Error(errorMessage(error)));
    } finally {
      await disposeCompletion();
      if (!res.writableEnded && !res.destroyed) {
        res.end();
      }
      if (!upstreamDone) {
        try {
          await iterator.return?.();
        } catch {
          // Upstream cleanup must not replace the response failure.
        }
      }
    }
  });

  // Assigned rather than decorated, so the method's type lives on GatewayInstance and nowhere in
  // Fastify's own interface.
  return Object.assign(app, {
    scopeCheckedRoutes: (): string[] => [...checkedPaths].sort(),
    residentBodyBytes: (): number => residentBodies.residentBytes,
  });
}
