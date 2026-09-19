import { afterAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  encodePopAuthorization,
  parsePopAuthorization,
  sha256Hex,
  signPopAuthorization,
  signingKeyFromSeed,
  toBase64Url,
  verifyPopSignature,
  type PopFields,
} from '@ashaveri/receipt';
import {
  AccessError,
  CredentialStore,
  ROUTE_SCOPES,
  newBearerCredential,
  newPopCredential,
  routeScope,
  type AdmissionInput,
  type CredentialRecord,
  type Scope,
} from '../src/access.js';

/**
 * Properties over the order `CredentialStore.admit` runs its checks in, and over what each refusal
 * costs the credential that presented it. The single-request cases in `admission.test.ts` pin three
 * pairs of neighbours; these say the same thing about every pair at once, and about the pairs no
 * single request happened to line up.
 */

/** Set from the environment so a red run replays exactly: `FC_SEED=1234` on the package's test run. */
const SEED = Number(process.env['FC_SEED'] ?? '20260918');

/** Kept low enough that the whole file runs in seconds; the walk below, not this, carries coverage. */
const RUNS = Number(process.env['FC_RUNS'] ?? '300');

const STARTED_AT = performance.now();
let propertyCalls = 0;
let predicateCalls = 0;
let walkedRows = 0;

/**
 * `fc.assert` fires the predicate `runs` times in total, and the pinned examples are the first
 * `examples.length` of those firings rather than extra runs on top of them. Measured on 4.10.1 at two
 * seeds: 10 runs with 3 examples is 10 firings, and 0 runs with 1 example is no firing at all. So this
 * counter is the call count, and adding the examples to it would double count every pinned case.
 */
function check<T>(arbitrary: fc.Arbitrary<T>, examples: readonly T[], predicate: (value: T) => boolean, runs: number = RUNS): void {
  propertyCalls += 1;
  predicateCalls += runs;
  fc.assert(fc.property(arbitrary, predicate), {
    numRuns: runs,
    seed: SEED,
    examples: examples.map((each) => [each] as [T]),
  });
}

const NOW_SECONDS = 1_772_000_000;
/** One frozen millisecond clock, so no case can refill a bucket while the test is counting it. */
const CLOCK_MS = NOW_SECONDS * 1000;

const RECORD_SEED = new Uint8Array(32).fill(0x21);
const FORGER_SEED = new Uint8Array(32).fill(0x22);
const RECORD_PUBLIC_KEY = signingKeyFromSeed(RECORD_SEED).publicKey;
const PROBE_ID = 'probe-svc';

/** A request target, which is the pair `routeScope` reads. */
interface HttpRoute {
  readonly method: string;
  readonly url: string;
}

/** Listed, satisfied by every scope set, and never the probe's own target: the pipeline's work route. */
const WORK_ROUTE: HttpRoute = { method: 'GET', url: '/v1/deployment-manifest' };

/** Listed, and needs `complete`, so a record without it is refused for the route it asked for. */
const COMPLETE_ROUTE: HttpRoute = { method: 'POST', url: '/v1/chat/completions' };

/** No row in the table names it, which is the only shape `routeScope` answers `undefined` for. */
const UNLISTED_ROUTE: HttpRoute = { method: 'GET', url: '/v1/not-a-route' };

/** The methods the table carries no row for. `HEAD` is deliberately absent: it normalizes to `GET`. */
const UNLISTED_METHODS: readonly string[] = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE'];

/**
 * The targets the route table does not name, spelled out of the table's own rows so the corpus moves
 * when the table moves. Each row is pushed outside the matcher in the ways it can be pushed: a method
 * with no row, a path past the end of the pattern, a trailing empty segment, and, for a row with a path
 * parameter, a value that fails the receipt id shape and one past its length cap. Everything kept has
 * been asked, not assumed, to answer `undefined`.
 */
function unlistedSpelledFrom(row: string, index: number): HttpRoute[] {
  const space = row.indexOf(' ');
  const listedMethod = row.slice(0, space);
  const pattern = row.slice(space + 1);
  const concrete = pattern.replace(':id', 'rcpt_01');
  const candidates: HttpRoute[] = [
    ...UNLISTED_METHODS.map((method) => ({ method, url: concrete })),
    { method: listedMethod, url: `${concrete}/past-the-end` },
    { method: listedMethod, url: `${concrete}/` },
  ];
  if (pattern.includes(':')) {
    candidates.push(
      { method: listedMethod, url: concrete.replace('rcpt_01', 'rcpt.01') },
      { method: listedMethod, url: concrete.replace('rcpt_01', '') },
      { method: listedMethod, url: concrete.replace('rcpt_01', `padded-${String(index)}-`.padEnd(65, 'x')) },
    );
  }
  return candidates.filter((each) => routeScope(each.method, each.url) === undefined);
}

const UNLISTED_TARGETS: readonly HttpRoute[] = Object.keys(ROUTE_SCOPES).flatMap(unlistedSpelledFrom);

/** Pinned below so a change to the route table has to be read before it is accepted. */
function corpusDigest(routes: readonly HttpRoute[]): string {
  return sha256Hex(Buffer.from(routes.map((each) => `${each.method} ${each.url}`).join('\n'), 'utf8'));
}

/** Which credential a measurement request is signed as. */
interface PresentationIdentity {
  readonly id: string;
  readonly key: Uint8Array;
}

/**
 * How many admissions a credential can still be granted, found by asking the store rather than by
 * reading a token count: there is none to read. The loop stops at the first refusal, so the answer is
 * the whole bucket, and a caller that presents the same request twice gets the same number both times.
 */
function admitCount(store: CredentialStore, who: PresentationIdentity, limit: number): number {
  let admitted = 0;
  for (let at = 0; at < limit; at++) {
    if (observe(() => store.admit(popRequest({ ...who, ...WORK_ROUTE, nonce: nonceAt(1_000 + at), stamp: 'fresh', withNonceHeader: true }))) !== 'no-error') {
      break;
    }
    admitted += 1;
  }
  return admitted;
}

/** A nonce per presentation, so one case's replay prime cannot collide with another case's request. */
function nonceAt(at: number): Uint8Array {
  const nonce = new Uint8Array(POP_NONCE_BYTES).fill(0x5a, 0, POP_NONCE_BYTES - 4);
  nonce[POP_NONCE_BYTES - 4] = (at >>> 24) & 0xff;
  nonce[POP_NONCE_BYTES - 3] = (at >>> 16) & 0xff;
  nonce[POP_NONCE_BYTES - 2] = (at >>> 8) & 0xff;
  nonce[POP_NONCE_BYTES - 1] = at & 0xff;
  return nonce;
}

/** The code a presentation answered with, or the name of whatever escaped the store instead. */
function observe(run: () => unknown): string {
  try {
    return run() === undefined ? 'undefined-admission' : 'no-error';
  } catch (err) {
    if (err instanceof AccessError) return err.code;
    const escaped = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return `escaped: ${escaped}`;
  }
}

interface PopRequestOptions {
  readonly id: string;
  readonly key: Uint8Array;
  readonly method: string;
  readonly url: string;
  readonly nonce: Uint8Array;
  readonly stamp: 'fresh' | 'stale';
  readonly withNonceHeader: boolean;
}

/**
 * Bytes the gateway accepts, built the way a client builds them. The method is upper-cased on the way
 * into the signing string and passed as presented on the way in, which is the only way a lowercase
 * method can be tested for a scope row without also testing it for a signature failure.
 */
function popRequest(options: PopRequestOptions): AdmissionInput {
  const fields: PopFields = {
    ts: options.stamp === 'stale' ? NOW_SECONDS - POP_TIMESTAMP_TOLERANCE_SECONDS - 1 : NOW_SECONDS,
    nonce: options.nonce,
    method: options.method.toUpperCase(),
    target: options.url,
    bodyDigestHex: EMPTY_BODY_SHA256_HEX,
  };
  const headers: Record<string, string> = { authorization: signPopAuthorization(fields, options.id, options.key) };
  if (options.withNonceHeader) headers['x-ashaveri-nonce'] = toBase64Url(options.nonce);
  return { method: options.method, url: options.url, headers, body: null, nowSeconds: NOW_SECONDS };
}

/**
 * Which record the probe's name resolves to. There is no state here for a `pop` record with no key
 * of the width its kind needs: the store refuses one when it takes its records, so a case that
 * wanted to stand for it would have no store to run against, and the refusal it used to pin is
 * pinned at construction instead.
 */
type Identity = 'known' | 'unknown' | 'revoked' | 'other-kind';
type Stamp = 'fresh' | 'stale';
type NonceHeader = 'present' | 'absent';
type Signature = 'valid' | 'forged';
type Presentation = 'first-time' | 'replayed';
type Target = 'entitled' | 'lacks-scope' | 'unlisted';
type Budget = 'has-tokens' | 'exhausted';

interface PopCase {
  identity: Identity;
  stamp: Stamp;
  nonceHeader: NonceHeader;
  signature: Signature;
  presentation: Presentation;
  target: Target;
  budget: Budget;
  burst: number;
}

/** A credential that resolves is the only credential whose later checks can be arranged at all. */
function resolves(c: PopCase): boolean {
  return c.identity === 'known';
}

/** What the store was actually left holding when the probe arrived, after the priming that could run. */
function effective(c: PopCase): PopCase {
  return resolves(c) ? c : { ...c, presentation: 'first-time', budget: 'has-tokens' };
}

const TARGET_ROUTE: Record<Target, HttpRoute> = {
  entitled: COMPLETE_ROUTE,
  'lacks-scope': COMPLETE_ROUTE,
  unlisted: UNLISTED_ROUTE,
};

/** The scopes a case's record holds, chosen so `target` says one thing and only that. */
function scopesFor(target: Target): Scope[] {
  return target === 'lacks-scope' ? ['read'] : ['read', 'complete'];
}

function recordsFor(c: PopCase): CredentialRecord[] {
  if (c.identity === 'other-kind') {
    return [newBearerCredential({ id: PROBE_ID, scopes: scopesFor(c.target), now: NOW_SECONDS }).record];
  }
  const generated = newPopCredential({ id: PROBE_ID, scopes: scopesFor(c.target), now: NOW_SECONDS });
  const record: CredentialRecord = {
    ...generated.record,
    ...(c.identity === 'unknown' ? { id: 'someone-else' } : {}),
    ...(c.identity === 'revoked' ? { revokedAt: NOW_SECONDS - 1 } : {}),
    publicKey: RECORD_PUBLIC_KEY,
    rate: { perMinute: 60, burst: c.burst },
  };
  return [record];
}

/**
 * The checks, in the order `admit` reaches them. This list is the claim: the first entry whose
 * condition holds is the code the client sees, and everything after it is not run. The two refusals
 * a request is owed whoever it names sit above the credential lookup, so they lead this list. A name
 * the file does not carry, a name carrying the other kind of record, and a signature that does not
 * verify are one answer given by one code path, so they are one entry here and it sits where the
 * signature has always sat; what the file says about a record whose key did verify starts at the
 * entry below it. Nothing in this list turns on the shape of the record it found: a `pop` record
 * carrying no key of the width its kind needs is refused where records enter the store, so no
 * request this walk sends can meet a 500 that names one id and not another.
 */
const CHECKS: ReadonlyArray<{ readonly code: string; readonly refuses: (c: PopCase) => boolean }> = [
  { code: 'AUTH_STALE', refuses: (c) => c.stamp === 'stale' },
  { code: 'AUTH_NONCE_MISSING', refuses: (c) => c.nonceHeader === 'absent' },
  {
    code: 'AUTH_SIGNATURE',
    refuses: (c) => c.identity === 'unknown' || c.identity === 'other-kind' || c.signature === 'forged',
  },
  { code: 'AUTH_REVOKED', refuses: (c) => c.identity === 'revoked' },
  { code: 'NONCE_SEEN', refuses: (c) => c.presentation === 'replayed' },
  { code: 'SCOPE_DENIED', refuses: (c) => c.target !== 'entitled' },
  { code: 'RATE_LIMITED', refuses: (c) => c.budget === 'exhausted' },
];

function expectedPopCode(c: PopCase): string {
  const state = effective(c);
  for (const step of CHECKS) {
    if (step.refuses(state)) return step.code;
  }
  return 'no-error';
}

interface PopRun {
  code: string;
  admitted: number;
}

/**
 * Rebuilds the state a case claims, presents the probe, then measures what the credential still has.
 * `withProbe` false runs the identical sequence without the probe in it, so the two numbers differ by
 * exactly what the probe took and the assertion does not depend on arithmetic about the priming.
 */
function runPopCase(c: PopCase, withProbe: boolean): PopRun {
  const store = new CredentialStore({ file: { version: 1, credentials: recordsFor(c) }, now: () => CLOCK_MS });
  const present = (input: AdmissionInput): string => observe(() => store.admit(input));
  const atWork = (nonce: Uint8Array): AdmissionInput =>
    popRequest({ id: PROBE_ID, key: RECORD_SEED, ...WORK_ROUTE, nonce, stamp: 'fresh', withNonceHeader: true });
  const probeNonce = nonceAt(0x8000);

  // The replay prime is a well-formed request for the work route, so it reaches the replay check
  // whatever the probe itself will be refused for. It is admitted, and that is the price of arranging
  // the state; the control run pays it too.
  if (resolves(c) && c.presentation === 'replayed') present(atWork(probeNonce));
  if (resolves(c) && c.budget === 'exhausted') {
    for (let at = 1; at <= c.burst; at++) {
      if (present(atWork(nonceAt(at))) !== 'no-error') break;
    }
  }

  let code = 'probe-withheld';
  if (withProbe) {
    const route = TARGET_ROUTE[c.target];
    code = present(
      popRequest({
        id: PROBE_ID,
        key: c.signature === 'valid' ? RECORD_SEED : FORGER_SEED,
        method: route.method,
        url: route.url,
        nonce: probeNonce,
        stamp: c.stamp,
        withNonceHeader: c.nonceHeader === 'present',
      }),
    );
  }
  return { code, admitted: admitCount(store, { id: PROBE_ID, key: RECORD_SEED }, c.burst + 2) };
}

interface BearerCase {
  allowBearer: boolean;
  match: boolean;
  revoked: boolean;
  target: Target;
  budget: Budget;
  burst: number;
  strangerSecret: Uint8Array;
}

/** A `Bearer` header over these bytes, which is the only spelling the pipeline itself sends. */
function bearerInput(route: HttpRoute, secret: Uint8Array): AdmissionInput {
  return {
    method: route.method,
    url: route.url,
    headers: { authorization: `Bearer ${Buffer.from(secret).toString('base64url')}` },
    body: null,
    nowSeconds: NOW_SECONDS,
  };
}

/**
 * What the bearer branch answers, in the order it answers: a deployment that has not opted in refuses
 * the scheme before it looks at a secret, a revoked record is skipped rather than refused by name, a
 * secret that matches nothing is the same refusal as a wrong secret, and only then the route and the
 * bucket. There is no nonce, no timestamp and no signature in this branch, so there is no step to
 * order against those either.
 */
const BEARER_CHECKS: ReadonlyArray<{ readonly code: string; readonly refuses: (c: BearerCase) => boolean }> = [
  { code: 'AUTH_SCHEME', refuses: (c) => !c.allowBearer },
  { code: 'AUTH_UNKNOWN', refuses: (c) => c.revoked },
  { code: 'AUTH_UNKNOWN', refuses: (c) => !c.match },
  { code: 'SCOPE_DENIED', refuses: (c) => c.target !== 'entitled' },
  { code: 'RATE_LIMITED', refuses: (c) => c.budget === 'exhausted' },
];

function expectedBearerCode(c: BearerCase): string {
  for (const step of BEARER_CHECKS) {
    if (step.refuses(c)) return step.code;
  }
  return 'no-error';
}

function runBearerCase(c: BearerCase, withProbe: boolean): PopRun {
  const enrolled = newBearerCredential({ id: 'ops-1', scopes: scopesFor(c.target), now: NOW_SECONDS });
  const record: CredentialRecord = {
    ...enrolled.record,
    ...(c.revoked ? { revokedAt: NOW_SECONDS - 1 } : {}),
    rate: { perMinute: 60, burst: c.burst },
  };
  // A proof-of-possession record sits beside the bearer one so the digest loop has to walk past a
  // record that carries no digest at all, which is the case that would otherwise read as a match.
  const intruder: CredentialRecord = {
    ...newPopCredential({ id: PROBE_ID, scopes: ['read', 'complete'], now: NOW_SECONDS }).record,
    publicKey: RECORD_PUBLIC_KEY,
  };
  const store = new CredentialStore({
    file: { version: 1, credentials: [intruder, record] },
    allowBearer: c.allowBearer,
    now: () => CLOCK_MS,
  });
  const secret = c.match ? enrolled.secret : c.strangerSecret;
  const present = (): string => observe(() => store.admit(bearerInput(TARGET_ROUTE[c.target], secret)));
  const atWork = (): string => observe(() => store.admit(bearerInput(WORK_ROUTE, secret)));
  if (c.budget === 'exhausted') {
    for (let at = 0; at < c.burst; at++) {
      if (atWork() !== 'no-error') break;
    }
  }
  const code = withProbe ? present() : 'probe-withheld';
  let admitted = 0;
  for (let at = 0; at < c.burst + 2; at++) {
    if (atWork() !== 'no-error') break;
    admitted += 1;
  }
  return { code, admitted };
}

const IDENTITIES: readonly Identity[] = ['known', 'unknown', 'revoked', 'other-kind'];
const STAMPS: readonly Stamp[] = ['fresh', 'stale'];
const NONCE_HEADERS: readonly NonceHeader[] = ['present', 'absent'];
const SIGNATURES: readonly Signature[] = ['valid', 'forged'];
const PRESENTATIONS: readonly Presentation[] = ['first-time', 'replayed'];
const TARGETS: readonly Target[] = ['entitled', 'lacks-scope', 'unlisted'];
const BUDGETS: readonly Budget[] = ['has-tokens', 'exhausted'];

const popCaseArbitrary: fc.Arbitrary<PopCase> = fc.record({
  identity: fc.constantFrom(...IDENTITIES),
  stamp: fc.constantFrom(...STAMPS),
  nonceHeader: fc.constantFrom(...NONCE_HEADERS),
  signature: fc.constantFrom(...SIGNATURES),
  presentation: fc.constantFrom(...PRESENTATIONS),
  target: fc.constantFrom(...TARGETS),
  budget: fc.constantFrom(...BUDGETS),
  burst: fc.integer({ min: 1, max: 3 }),
});

/** Every combination, at the burst that keeps the walk a second rather than a minute. */
function allPopCases(): PopCase[] {
  const cases: PopCase[] = [];
  for (const identity of IDENTITIES) {
    for (const stamp of STAMPS) {
      for (const nonceHeader of NONCE_HEADERS) {
        for (const signature of SIGNATURES) {
          for (const presentation of PRESENTATIONS) {
            for (const target of TARGETS) {
              for (const budget of BUDGETS) {
                cases.push({ identity, stamp, nonceHeader, signature, presentation, target, budget, burst: 2 });
              }
            }
          }
        }
      }
    }
  }
  return cases;
}

describe('the order admit runs the five checks in', () => {
  it('walks every combination of the checks and reports the first one that fails', { timeout: 120_000 }, () => {
    const rows = allPopCases();
    walkedRows += rows.length;
    const mismatches: string[] = [];
    for (const each of rows) {
      const expected = expectedPopCode(each);
      const observed = runPopCase(each, true).code;
      if (observed !== expected) mismatches.push(`${JSON.stringify(each)} answered ${observed}, first failing check is ${expected}`);
    }
    // Sampled properties can miss the one combination two checks disagree about, and this claim is
    // exactly about a pair of neighbours, so it is walked rather than drawn.
    expect(mismatches, mismatches.slice(0, 3).join('\n')).toHaveLength(0);
  });

  it('leaves the bucket exactly where a refusal found it, over random combinations', () => {
    const replayedBeforeScope: PopCase = {
      identity: 'known',
      stamp: 'fresh',
      nonceHeader: 'present',
      signature: 'valid',
      presentation: 'replayed',
      target: 'lacks-scope',
      budget: 'has-tokens',
      burst: 1,
    };
    const replayedAgainstAnEmptyBucket: PopCase = { ...replayedBeforeScope, budget: 'exhausted' };
    const forgedAgainstAnEmptyBucket: PopCase = {
      ...replayedBeforeScope,
      presentation: 'first-time',
      signature: 'forged',
      budget: 'exhausted',
    };
    const admitted: PopCase = { ...replayedBeforeScope, presentation: 'first-time', target: 'entitled' };
    check(
      popCaseArbitrary,
      [replayedBeforeScope, replayedAgainstAnEmptyBucket, forgedAgainstAnEmptyBucket, admitted],
      (each) => {
        const expected = expectedPopCode(each);
        const probe = runPopCase(each, true);
        const control = runPopCase(each, false);
        if (probe.code !== expected) return false;
        // A refusal before the spend leaves the count alone, and an admission takes exactly one. The
        // second half is what stops the first from passing on a store that never reaches a bucket: with
        // no admitted case in the corpus the two numbers would be equal for every input.
        return probe.admitted === control.admitted - (expected === 'no-error' ? 1 : 0);
      },
    );
  });

  it('counts what a refused request did not spend, on a bucket small enough to read', () => {
    for (const target of TARGETS) {
      for (const signature of SIGNATURES) {
        for (const presentation of PRESENTATIONS) {
          for (const budget of BUDGETS) {
            const c: PopCase = {
              identity: 'known',
              stamp: 'fresh',
              nonceHeader: 'present',
              signature,
              presentation,
              target,
              budget,
              burst: 3,
            };
            const probe = runPopCase(c, true);
            const control = runPopCase(c, false);
            const expected = expectedPopCode(c);
            // Named numbers, so a reader can check the arithmetic instead of trusting the helper: three
            // tokens, one of them gone to the replay prime where the case asks for one. Draining spends
            // whatever the prime left and stops at the refusal that says so, so an exhausted bucket is
            // empty rather than overdrawn, and only an admitted probe takes a token after that.
            const primed = presentation === 'replayed' ? 1 : 0;
            const standing = 3 - primed;
            const spent = expected === 'no-error' ? 1 : 0;
            const controlAdmitted = budget === 'exhausted' ? 0 : standing;
            expect(probe.code, JSON.stringify(c)).toBe(expected);
            expect(control.admitted, JSON.stringify({ c, role: 'control' })).toBe(controlAdmitted);
            expect(probe.admitted, JSON.stringify({ c, role: 'probe' })).toBe(controlAdmitted - spent);
          }
        }
      }
    }
  });

  it('refuses an Authorization header it cannot read before it looks a credential up', () => {
    // No `=` and no space in this alphabet, so no text drawn from it can carry a `name=value`
    // parameter or the `Bearer ` prefix: whatever the store answers, it answered at the door, and
    // the two refusal codes are decided by the first token alone. A tab or a newline is a token
    // separator here, so `Ashaveri-PoP` must be the whole of it: a longer token such as
    // `Ashaveri-PoPzz` is somebody else's scheme, which is a scheme disagreement and not a
    // malformed one. This is the codec's rule restated, not imported from it, so the property
    // checks the gateway against an expectation a reader can audit by eye.
    const alphabet = fc.constantFrom(...[...'Ashaveri-PoPabcXYZ019-_/+.\t\n'].filter((char) => char !== ' '));
    const headerText = fc.array(alphabet, { maxLength: 40 }).map((chars) => chars.join(''));
    check(headerText, ['', ' ', '\t', 'Ashaveri-PoP', 'Ashaveri-PoPzz', 'Basic abc', 'bearer abc'], (text) => {
      const trimmed = text.trim();
      const firstToken = trimmed.split(/\s+/u)[0];
      const expected = trimmed.length === 0 ? 'AUTH_MALFORMED' : firstToken === 'Ashaveri-PoP' ? 'AUTH_MALFORMED' : 'AUTH_SCHEME';
      const store = new CredentialStore({
        file: {
          version: 1,
          credentials: [
            {
              ...newPopCredential({ id: PROBE_ID, scopes: ['read', 'complete'], now: NOW_SECONDS }).record,
              publicKey: RECORD_PUBLIC_KEY,
              rate: { perMinute: 60, burst: 1 },
            },
          ],
        },
        now: () => CLOCK_MS,
      });
      const answer = observe(() => store.admit({ method: 'GET', url: WORK_ROUTE.url, headers: { authorization: text }, body: null, nowSeconds: NOW_SECONDS }));
      if (answer !== expected) return false;
      // The door is not a place to spend: one token, presented a hundred unreadable headers, is still
      // one token for the request that does arrive.
      return admitCount(store, { id: PROBE_ID, key: RECORD_SEED }, 3) === 1;
    });
  });

  it('runs the bearer checks in the order resolve, then scope, then spend', () => {
    const bearerCaseArbitrary: fc.Arbitrary<BearerCase> = fc.record({
      allowBearer: fc.boolean(),
      match: fc.boolean(),
      revoked: fc.boolean(),
      target: fc.constantFrom(...TARGETS),
      budget: fc.constantFrom(...BUDGETS),
      burst: fc.integer({ min: 1, max: 3 }),
      strangerSecret: fc.uint8Array({ minLength: 32, maxLength: 32 }),
    });
    check(
      bearerCaseArbitrary,
      [
        { allowBearer: true, match: true, revoked: false, target: 'unlisted', budget: 'has-tokens', burst: 1, strangerSecret: new Uint8Array(32) },
        { allowBearer: true, match: true, revoked: false, target: 'lacks-scope', budget: 'exhausted', burst: 1, strangerSecret: new Uint8Array(32) },
        { allowBearer: true, match: false, revoked: false, target: 'entitled', budget: 'has-tokens', burst: 1, strangerSecret: new Uint8Array(32) },
      ],
      (each) => {
        const expected = expectedBearerCode(each);
        const probe = runBearerCase(each, true);
        const control = runBearerCase(each, false);
        if (probe.code !== expected) return false;
        return probe.admitted === control.admitted - (expected === 'no-error' ? 1 : 0);
      },
    );
  });

  it('answers the same way twice for a bearer scope miss, because a bearer request carries no nonce', () => {
    const enrolled = newBearerCredential({ id: 'ops-1', scopes: ['read'], now: NOW_SECONDS });
    const store = new CredentialStore({
      file: { version: 1, credentials: [{ ...enrolled.record, rate: { perMinute: 60, burst: 1 } }] },
      allowBearer: true,
      now: () => CLOCK_MS,
    });
    const denied = (): string => observe(() => store.admit(bearerInput(TARGET_ROUTE['lacks-scope'], enrolled.secret)));
    // A proof of possession refused for its route is refused for its nonce the second time, because the
    // nonce is spent before the route is read. A bearer request has no nonce to spend, so the only
    // state a repeat can find is the bucket, and this says the scope refusal left that alone too.
    expect(denied()).toBe('SCOPE_DENIED');
    expect(denied()).toBe('SCOPE_DENIED');
    expect(denied()).toBe('SCOPE_DENIED');
    expect(observe(() => store.admit(bearerInput(WORK_ROUTE, enrolled.secret)))).toBe('no-error');
    expect(observe(() => store.admit(bearerInput(WORK_ROUTE, enrolled.secret)))).toBe('RATE_LIMITED');
  });
});

interface UnlistedPopCase {
  keySeed: Uint8Array;
  credential: string;
  scopes: Scope[];
  route: HttpRoute;
  nonce: Uint8Array;
  burst: number;
}

interface UnlistedBearerCase {
  credential: string;
  scopes: Scope[];
  route: HttpRoute;
  repeats: number;
  burst: number;
}

/** The grants a record can hold, including none: the refusal these cases test is about the table row. */
const NO_GRANTS: Scope[] = [];
const READ_ONLY: Scope[] = ['read'];
const COMPLETE_ONLY: Scope[] = ['complete'];
const ALL_GRANTS: Scope[] = ['read', 'complete'];
const SCOPE_SETS: readonly Scope[][] = [NO_GRANTS, READ_ONLY, COMPLETE_ONLY, ALL_GRANTS];

/** A path the table reaches, under a method it has no row for. */
const WRONG_METHOD_ROUTE: HttpRoute = { method: 'PUT', url: COMPLETE_ROUTE.url };

/** A table method over an empty path parameter, which is a segment and matches no id shape. */
const EMPTY_PARAMETER_ROUTE: HttpRoute = { method: 'GET', url: '/v1/receipts/' };

/** The work route, spelled with a method no HTTP router here answers on. */
const UNANSWERED_METHOD_ROUTE: HttpRoute = { method: 'TRACE', url: WORK_ROUTE.url };

/** The count's own request, and never the one a case is probing with. */
const CONTROL_NONCE = nonceAt(9_000);

const unlistedPopCaseArbitrary: fc.Arbitrary<UnlistedPopCase> = fc.record({
  keySeed: fc.uint8Array({ minLength: 32, maxLength: 32 }),
  credential: fc.constantFrom('edge-svc', 'core-svc', 'batch-runner'),
  scopes: fc.constantFrom(...SCOPE_SETS),
  route: fc.constantFrom(...UNLISTED_TARGETS),
  nonce: fc.uint8Array({ minLength: POP_NONCE_BYTES, maxLength: POP_NONCE_BYTES }),
  burst: fc.integer({ min: 1, max: 3 }),
});

const unlistedBearerCaseArbitrary: fc.Arbitrary<UnlistedBearerCase> = fc.record({
  credential: fc.constantFrom('ops-1', 'ops-2', 'edge-key'),
  scopes: fc.constantFrom(...SCOPE_SETS),
  route: fc.constantFrom(...UNLISTED_TARGETS),
  repeats: fc.integer({ min: 1, max: 5 }),
  burst: fc.integer({ min: 1, max: 3 }),
});

/**
 * What a draw cost, read off two stores rather than one: the refusal the case asks for, the entitled
 * control request, and how much either left behind.
 */
interface Cost {
  refusal: string;
  control: string;
  afterRefusal: number;
  afterControl: number;
}

/**
 * The count is always the last thing either store is asked for. Counting drains the bucket it measures,
 * and a bucket belongs to a credential rather than to a route, so no second reading of one is possible
 * and the two readings the claim needs have to come from two stores built the same way. `afterRefusal`
 * is the claim; `afterControl` is the control on the very same number, and one admitted request in
 * front of the count moves it by exactly one.
 */
function unlistedPopCost(c: UnlistedPopCase): Cost {
  const record: CredentialRecord = {
    ...newPopCredential({ id: c.credential, scopes: c.scopes, now: NOW_SECONDS }).record,
    publicKey: signingKeyFromSeed(c.keySeed).publicKey,
    rate: { perMinute: 60, burst: c.burst },
  };
  const who: PresentationIdentity = { id: record.id, key: c.keySeed };
  const run = (withControl: boolean): { refusal: string; control: string; left: number } => {
    const store = new CredentialStore({ file: { version: 1, credentials: [record] }, now: () => CLOCK_MS });
    const ask = (route: HttpRoute, nonce: Uint8Array): string =>
      observe(() => store.admit(popRequest({ ...who, ...route, nonce, stamp: 'fresh', withNonceHeader: true })));
    const refusal = ask(c.route, c.nonce);
    const control = withControl ? ask(WORK_ROUTE, CONTROL_NONCE) : 'control-withheld';
    return { refusal, control, left: admitCount(store, who, c.burst + 1) };
  };
  const plain = run(false);
  const spent = run(true);
  return { refusal: plain.refusal, control: spent.control, afterRefusal: plain.left, afterControl: spent.left };
}

/** The same two stores for the bearer branch, with the refusal presented a drawn number of times. */
function unlistedBearerCost(c: UnlistedBearerCase): Cost {
  const enrolled = newBearerCredential({ id: c.credential, scopes: c.scopes, now: NOW_SECONDS });
  const record: CredentialRecord = { ...enrolled.record, rate: { perMinute: 60, burst: c.burst } };
  // The proof-of-possession record beside it carries no digest, so the loop that looks for the secret
  // has to read past a record that cannot answer before it reaches the one that does.
  const intruder: CredentialRecord = {
    ...newPopCredential({ id: PROBE_ID, scopes: ALL_GRANTS, now: NOW_SECONDS }).record,
    publicKey: RECORD_PUBLIC_KEY,
  };
  const run = (withControl: boolean): { refusal: string; control: string; left: number } => {
    const store = new CredentialStore({
      file: { version: 1, credentials: [intruder, record] },
      allowBearer: true,
      now: () => CLOCK_MS,
    });
    const ask = (route: HttpRoute): string => observe(() => store.admit(bearerInput(route, enrolled.secret)));
    const codes: string[] = [];
    for (let at = 0; at < c.repeats; at++) codes.push(ask(c.route));
    // A bearer request carries no nonce, so this is the whole of "the replay set gains nothing" that the
    // branch can be asked: a presentation repeated has to come back the same code, because a code that
    // changed would be the sign of state the first presentation left behind.
    const distinct = [...new Set(codes)];
    const refusal = distinct.length === 1 ? distinct[0] ?? 'none' : `diverged: ${distinct.join(', ')}`;
    const control = withControl ? ask(WORK_ROUTE) : 'control-withheld';
    return { refusal, control, left: admitBearerCount(store, enrolled.secret, c.burst + 1) };
  };
  const plain = run(false);
  const spent = run(true);
  return { refusal: plain.refusal, control: spent.control, afterRefusal: plain.left, afterControl: spent.left };
}

/** Bearer counting needs the store's own digest loop, so this one takes the credential it is told. */
function admitBearerCount(store: CredentialStore, secret: Uint8Array, limit: number): number {
  let admitted = 0;
  for (let at = 0; at < limit; at++) {
    if (observe(() => store.admit(bearerInput(WORK_ROUTE, secret))) !== 'no-error') break;
    admitted += 1;
  }
  return admitted;
}

describe('what a target the route table does not name costs', () => {
  it('refuses a target outside the table and takes nothing for it, in proof of possession', { timeout: 60_000 }, () => {
    check(
      unlistedPopCaseArbitrary,
      [
        { keySeed: RECORD_SEED, credential: PROBE_ID, scopes: ALL_GRANTS, route: UNLISTED_ROUTE, nonce: nonceAt(21), burst: 1 },
        { keySeed: RECORD_SEED, credential: PROBE_ID, scopes: NO_GRANTS, route: WRONG_METHOD_ROUTE, nonce: nonceAt(22), burst: 3 },
        { keySeed: FORGER_SEED, credential: 'edge-svc', scopes: ALL_GRANTS, route: EMPTY_PARAMETER_ROUTE, nonce: nonceAt(23), burst: 2 },
      ],
      (c) => {
        // The premise, asked of the code on every draw rather than assumed from how the route was built.
        if (routeScope(c.route.method, c.route.url) !== undefined) return false;
        const cost = unlistedPopCost(c);
        return (
          cost.refusal === 'SCOPE_DENIED' &&
          cost.control === 'no-error' &&
          cost.afterRefusal === c.burst &&
          cost.afterControl === c.burst - 1
        );
      },
    );
  });

  it('refuses a target outside the table and takes nothing for it, over bearer', () => {
    check(
      unlistedBearerCaseArbitrary,
      [
        { credential: 'ops-1', scopes: ALL_GRANTS, route: UNLISTED_ROUTE, repeats: 5, burst: 1 },
        { credential: 'ops-2', scopes: NO_GRANTS, route: UNANSWERED_METHOD_ROUTE, repeats: 3, burst: 3 },
      ],
      (c) => {
        if (routeScope(c.route.method, c.route.url) !== undefined) return false;
        const cost = unlistedBearerCost(c);
        return (
          cost.refusal === 'SCOPE_DENIED' &&
          cost.control === 'no-error' &&
          cost.afterRefusal === c.burst &&
          cost.afterControl === c.burst - 1
        );
      },
    );
  });

  it('keeps the nonce of a proof-of-possession request it refused for its target', () => {
    const record: CredentialRecord = {
      ...newPopCredential({ id: PROBE_ID, scopes: ['read', 'complete'], now: NOW_SECONDS }).record,
      publicKey: RECORD_PUBLIC_KEY,
      rate: { perMinute: 60, burst: 10 },
    };
    const ask = (store: CredentialStore, route: HttpRoute, at: number): string =>
      observe(() => store.admit(popRequest({ id: PROBE_ID, key: RECORD_SEED, ...route, nonce: nonceAt(at), stamp: 'fresh', withNonceHeader: true })));

    // The replay check sits before the scope check, so the nonce a refused request presented is kept
    // and its second presentation is refused for the nonce rather than for the route. The route table
    // is not consulted first, which is the point: reading it first would let anyone enumerate which
    // paths this gateway has scoped.
    const outside = new CredentialStore({ file: { version: 1, credentials: [record] }, now: () => CLOCK_MS });
    expect(ask(outside, UNLISTED_ROUTE, 11)).toBe('SCOPE_DENIED');
    expect(ask(outside, UNLISTED_ROUTE, 11)).toBe('NONCE_SEEN');
    expect(ask(outside, UNLISTED_ROUTE, 12)).toBe('SCOPE_DENIED');

    // Same shape on a listed route the record has no grant for, so the kept nonce is the order of the
    // checks and not something about a target with no row.
    const ungranted = new CredentialStore({ file: { version: 1, credentials: [{ ...record, scopes: READ_ONLY }] }, now: () => CLOCK_MS });
    expect(ask(ungranted, COMPLETE_ROUTE, 13)).toBe('SCOPE_DENIED');
    expect(ask(ungranted, COMPLETE_ROUTE, 13)).toBe('NONCE_SEEN');
    expect(ask(ungranted, COMPLETE_ROUTE, 14)).toBe('SCOPE_DENIED');
  });

  it('derives the corpus its targets come from out of the route table, and pins that corpus', () => {
    // These are the draws the two properties above make from, so the corpus is their domain. It is
    // spelled out of `ROUTE_SCOPES` instead of typed out by hand, and the digest is what makes a change
    // to the table arrive as a failing test rather than as a quietly smaller set of targets.
    expect(corpusDigest(UNLISTED_TARGETS)).toBe('c3589fce857b75e9473cd2f8e103d8c2148a98bd05a04de297b110cc8ab9512f');
    expect(UNLISTED_TARGETS.length).toBe(38);
    // Two shapes, not one trick: a table path under a method the table has no row for, and a table
    // method over a path its pattern does not reach.
    expect(routeScope('PUT', COMPLETE_ROUTE.url)).toBeUndefined();
    expect(routeScope('POST', COMPLETE_ROUTE.url)).toBe('complete');
    expect(routeScope('GET', '/v1/receipts/rcpt.01')).toBeUndefined();
    expect(routeScope('GET', '/v1/receipts/rcpt_01')).toBe('read');
    // `HEAD` is GET without a body and Fastify answers it on every GET route, so it is listed and has
    // no business being in a corpus of unlisted targets.
    expect(routeScope('HEAD', WORK_ROUTE.url)).toBe('any');
    expect(routeScope('HEAD', '/v1/attestation')).toBe('read');
    expect(UNLISTED_TARGETS.some((each) => each.method === 'HEAD')).toBe(false);
  });
});

/** Above the other properties, and settable, because the sweep below is the expensive measurement. */
const SWEEP_RUNS = Number(process.env['FC_SWEEP'] ?? '100000');

/** The fields the verifier is handed, so a case varies only the bytes it is attacking. */
const SWEEP_FIELDS: PopFields = {
  ts: NOW_SECONDS,
  nonce: nonceAt(31),
  method: 'GET',
  target: WORK_ROUTE.url,
  bodyDigestHex: EMPTY_BODY_SHA256_HEX,
};

/** A signature this key really made, which is the sweep's one accepted verdict. */
const SIGNED_FIELDS = parsePopAuthorization(signPopAuthorization(SWEEP_FIELDS, PROBE_ID, RECORD_SEED));

/**
 * Encodings at the edges of the field a public key is read in: the prime 2^255-19, its neighbour
 * below, the value one past it, the largest the width can hold, and the sign bit of the last byte
 * cleared and set across those. This is not the small-order acceptor class, which the receipt
 * package's own suite pins. What is claimed here is narrower: that none of these encodings throws.
 */
function fieldEdgeKeys(): Uint8Array[] {
  const prime = new Uint8Array(32).fill(0xff);
  prime[0] = 0xed;
  prime[31] = 0x7f;
  const topByte = prime[31] ?? 0;
  const atEdge = (lowByte: number, highByte: number): Uint8Array => {
    const key = prime.slice();
    key[0] = lowByte;
    key[31] = highByte;
    return key;
  };
  return [
    new Uint8Array(32),
    new Uint8Array(32).fill(0x01),
    new Uint8Array(32).fill(0xff),
    prime.slice(),
    atEdge(0xee, topByte),
    atEdge(0xee, 0xff),
    atEdge(0xef, topByte),
    atEdge(0xff, 0x7f),
    atEdge(0x00, 0x80),
    atEdge(0xed, 0xff),
  ];
}

const HOSTILE_KEYS: readonly Uint8Array[] = fieldEdgeKeys();

function keyCorpusDigest(keys: readonly Uint8Array[]): string {
  return sha256Hex(Buffer.from(keys.map((key) => Buffer.from(key).toString('hex')).join('\n'), 'utf8'));
}

interface VerifyCase {
  signature: Uint8Array;
  publicKey: Uint8Array;
}

interface WidthCase {
  signatureWidth: number;
  keyWidth: number;
}

interface RefusalCase {
  recordKey: Uint8Array;
  signerSeed: Uint8Array;
  signedByRecord: boolean;
}

const verifyCaseArbitrary: fc.Arbitrary<VerifyCase> = fc.record({
  signature: fc.uint8Array({ minLength: 64, maxLength: 64 }),
  publicKey: fc.uint8Array({ minLength: 32, maxLength: 32 }),
});

const widthCaseArbitrary: fc.Arbitrary<WidthCase> = fc.record({
  signatureWidth: fc.integer({ min: 0, max: 129 }),
  keyWidth: fc.integer({ min: 0, max: 33 }),
});

const refusalCaseArbitrary: fc.Arbitrary<RefusalCase> = fc.record({
  recordKey: fc.oneof(...HOSTILE_KEYS.map((key) => fc.constant(key)), fc.uint8Array({ minLength: 32, maxLength: 32 })),
  signerSeed: fc.uint8Array({ minLength: 32, maxLength: 32 }),
  signedByRecord: fc.boolean(),
});

/**
 * One presentation, one store, the code it answered with. The record's key is the drawn one unless the
 * case asks for the signer's own, which is the control: without a presentation that gets through, a
 * verifier that refused everything would read the same as one that refused the right things.
 */
function refusalCode(c: RefusalCase): string {
  const record: CredentialRecord = {
    ...newPopCredential({ id: PROBE_ID, scopes: ALL_GRANTS, now: NOW_SECONDS }).record,
    publicKey: c.signedByRecord ? signingKeyFromSeed(c.signerSeed).publicKey : c.recordKey,
    rate: { perMinute: 60, burst: 1 },
  };
  const store = new CredentialStore({ file: { version: 1, credentials: [record] }, now: () => CLOCK_MS });
  return observe(() =>
    store.admit(
      popRequest({ id: PROBE_ID, key: c.signerSeed, ...WORK_ROUTE, nonce: nonceAt(41), stamp: 'fresh', withNonceHeader: true }),
    ),
  );
}

/** What the sweep saw, printed because the question asks for counts and not for a green tick. */
let sweepAccepted = 0;
let sweepRefused = 0;

describe('what the signature check answers when it cannot check', () => {
  it('tells a refusal from a throw, on a call that genuinely throws', () => {
    // The no-throw measurements below read "returned" out of one catcher. This hands the same catcher a
    // call that does throw, a signature asked of a nonce the wire format will not carry, and then the
    // call it is meant to distinguish: returning false and throwing are two events, and only a case
    // that shows both says the instrument can tell them apart.
    const threw = observe(() => signPopAuthorization({ ...SWEEP_FIELDS, nonce: new Uint8Array(8) }, PROBE_ID, RECORD_SEED));
    expect(threw.startsWith('escaped:')).toBe(true);
    const verdict = verifyPopSignature(SWEEP_FIELDS, new Uint8Array(64).fill(0x41), RECORD_PUBLIC_KEY);
    expect(verdict).toBe(false);
    expect(observe(() => verifyPopSignature(SWEEP_FIELDS, new Uint8Array(64).fill(0x41), RECORD_PUBLIC_KEY))).toBe('no-error');
  });

  it('verifies a hundred thousand keys and signatures without throwing', { timeout: 300_000 }, () => {
    check(
      verifyCaseArbitrary,
      [{ signature: SIGNED_FIELDS.signature, publicKey: RECORD_PUBLIC_KEY }],
      (c) => {
        const verdict = verifyPopSignature(SWEEP_FIELDS, c.signature, c.publicKey);
        if (typeof verdict !== 'boolean') return false;
        if (verdict) sweepAccepted += 1;
        else sweepRefused += 1;
        return true;
      },
      SWEEP_RUNS,
    );
    process.stdout.write(
      `access-order: verify swept ${String(sweepAccepted + sweepRefused)} calls, ${String(sweepAccepted)} accepted, ` +
        `${String(sweepRefused)} refused, 0 thrown\n`,
    );
    // A throw would have ended the run with a counterexample rather than reaching here, so these
    // numbers are the measurement. The accepted verdict is the one signature this key really made, and
    // it is a pinned example, which `fc.assert` draws as the first of the `SWEEP_RUNS` calls rather
    // than as an extra one, so the refusals are one short of the run count and the two sum to it.
    // Lowering `FC_SWEEP` to 0 asks for no calls at all and leaves this sum false rather than quietly
    // true, because nothing below one accepted example is being measured.
    expect(sweepAccepted).toBe(1);
    expect(sweepAccepted + sweepRefused).toBe(SWEEP_RUNS);
  });

  it('answers with a boolean whatever width it is handed', () => {
    check(
      widthCaseArbitrary,
      [
        { signatureWidth: 0, keyWidth: 0 },
        { signatureWidth: 63, keyWidth: 32 },
        { signatureWidth: 64, keyWidth: 31 },
        { signatureWidth: 64, keyWidth: 32 },
        { signatureWidth: 64, keyWidth: 33 },
        { signatureWidth: 65, keyWidth: 32 },
        { signatureWidth: 128, keyWidth: 32 },
      ],
      (c) =>
        typeof verifyPopSignature(
          SWEEP_FIELDS,
          new Uint8Array(c.signatureWidth).fill(0x5a),
          new Uint8Array(c.keyWidth).fill(0xa5),
        ) === 'boolean',
    );
  });

  it('answers AUTH_SIGNATURE for a presentation it cannot verify, whatever key the record carries', { timeout: 60_000 }, () => {
    check(
      refusalCaseArbitrary,
      [
        { recordKey: new Uint8Array(32), signerSeed: RECORD_SEED, signedByRecord: false },
        { recordKey: new Uint8Array(32).fill(0xff), signerSeed: FORGER_SEED, signedByRecord: false },
        { recordKey: HOSTILE_KEYS[0] ?? new Uint8Array(32), signerSeed: RECORD_SEED, signedByRecord: true },
      ],
      (c) => {
        const code = refusalCode(c);
        // Anything that is not an `AccessError` is rethrown by the request pipeline, so an escape here is
        // a client that asked for a signature check and got a server error instead of a refusal.
        if (code.startsWith('escaped:')) return false;
        return code === (c.signedByRecord ? 'no-error' : 'AUTH_SIGNATURE');
      },
    );
  });

  it('refuses a record whose key is the wrong width where records enter the store', () => {
    const keyWidthArbitrary: fc.Arbitrary<number> = fc.oneof(fc.integer({ min: 0, max: 31 }), fc.integer({ min: 33, max: 96 }));
    check(keyWidthArbitrary, [0, 1, 31, 33, 64, 96], (width) => {
      const record: CredentialRecord = {
        ...newPopCredential({ id: PROBE_ID, scopes: ALL_GRANTS, now: NOW_SECONDS }).record,
        publicKey: new Uint8Array(width).fill(0xed),
        rate: { perMinute: 60, burst: 1 },
      };
      // The store refuses the record and the request is never asked. The claim this replaces was that
      // `admit` answered `BAD_CREDENTIAL_RECORD` rather than letting the short bytes reach the
      // verifier, where they would answer `AUTH_SIGNATURE` and blame a client's signature for the
      // store's own record; that half still has to hold, and the only way to hold it without also
      // giving one id a 500 and another a 401 is to refuse the record before any request names it.
      // `admission.test.ts` pins the same refusal through the parser, which is where this rule came
      // from: the bytes above are the file a deployment cannot load, handed in as an object.
      return observe(() => new CredentialStore({ file: { version: 1, credentials: [record] }, now: () => CLOCK_MS })) === 'BAD_CREDENTIAL_RECORD';
    });
  });

  it('draws from the hostile key corpus it was hashed against', () => {
    // The corpus is arithmetic, not a list of bytes to paste, so the digest is what says which encodings
    // the gate above actually asked about. A changed field prime or a dropped edge is a different corpus
    // and should read as a failing test.
    expect(HOSTILE_KEYS.length).toBe(10);
    expect(HOSTILE_KEYS.every((key) => key.length === 32)).toBe(true);
    expect(keyCorpusDigest(HOSTILE_KEYS)).toBe('7b865932990e195d028c34d6f065e0904c0b075c06951c37e71589c52e4aba77');
  });
});

/**
 * Two stores that differ in exactly one way: one of them holds a record named `probe-svc` and the other
 * holds nothing named `probe-svc`. Both hold the same two unrelated records, so the second is a
 * credential file with a hole in it rather than an empty one. For every request shape the gateway can be
 * given, the two must answer with the same code, the same status and the same words, and neither may
 * answer by serving the request.
 *
 * What that guards is the question a caller can otherwise ask about which ids this file holds. Every
 * refusal on the proof-of-possession path is reached by reading the record the header names, so any one
 * of them given for a name and withheld for another tells the caller the name is there. The only answer
 * allowed to depend on the file is the one given after the request has proved it holds the key its own
 * header names.
 *
 * `proves` is how this walk records that the test itself made such a request: it signed the bytes with
 * the secret whose public key it then wrote into the record. That is a fact about how the request was
 * built, not about what a verifier answered, and the difference matters because a signature can verify
 * for the wrong reason. `verifyPopSignature` is strict where the library under it is relaxed, and the
 * relaxation is measurable: on the installed `@noble/curves`, `ed25519.verify` with its own defaults
 * answers true for a run of 64 zero bytes against an all-zero 32-byte key, the identity point of the
 * torsion subgroup, for any message at all, where `verifyPopSignature` answers false. The strict side
 * is pinned for every encoding of every small-order key at `packages/receipt/test/pop.test.ts:278`. So
 * a store that reached for the library directly, or that read a `true` from a placeholder key as
 * permission to carry on, would serve a request naming a record it does not hold, and a property stated
 * in terms of what verified would have filtered out exactly that shape. The clause that nothing is
 * served therefore has no exception at all, and the acceptor class sits inside the matrix rather than
 * under it: `small-order-key` puts that very key in the record and `unsigned/zero-signature` presents
 * those very bytes.
 *
 * Every cell is walked rather than drawn, because the matrix is small and a cell that never arrives is a
 * hole in the property nobody would notice. Set `TWO_STORE_MATRIX=1` on the run to print all of it; the
 * divergences are printed either way.
 */

/** A record both stores hold, so the walk can see what an admission looks like in each of them. */
const SHARED_NAME = 'edge-svc';
const SHARED_SEED = new Uint8Array(32).fill(0x23);
const SHARED_PUBLIC_KEY = signingKeyFromSeed(SHARED_SEED).publicKey;
/** A bearer secret enrolled in neither store, so a bearer request that matches nothing is refused twice. */
const UNENROLLED_SECRET = new Uint8Array(32).fill(0x24);

const STALE_TS = NOW_SECONDS - POP_TIMESTAMP_TOLERANCE_SECONDS - 1;
/** One nonce for every shape, so the only thing a shape varies is the header that carries it. */
const SHAPE_NONCE = nonceAt(0x1430);
const ANOTHER_NONCE = nonceAt(0x1431);
const ZERO_SIGNATURE = new Uint8Array(64);
const SATURATED_SIGNATURE = new Uint8Array(64).fill(0xff);

/**
 * The states `N` is put into: the record axis ranges over what the file says about it, not just
 * whether it is there.
 *
 * A wrong-width key is not on this axis any more, because the store will not hold one: it is refused
 * where records enter, so the state cannot be built and there is no answer for either store to
 * disagree about. `pop-with-secret-hash` stays, and stays as it is written, because the field is the
 * point: a file read from disk never carries it, so this is the state that asks whether the in-memory
 * route holds the same record the parser would have produced.
 */
type ProbedState = 'live-pop' | 'revoked-pop' | 'bearer' | 'small-order-key' | 'pop-with-secret-hash';

const PROBED_STATES: readonly ProbedState[] = [
  'live-pop',
  'revoked-pop',
  'bearer',
  'small-order-key',
  'pop-with-secret-hash',
];

interface Probed {
  readonly state: ProbedState;
  readonly record: CredentialRecord;
  /** The secret whose public key the record carries, or nothing when the test cannot sign as this record. */
  readonly ownKey: Uint8Array | null;
  /** The bearer secret this record matches, or one that matches no record in either store. */
  readonly bearerSecret: Uint8Array;
}

function probedAs(state: ProbedState): Probed {
  if (state === 'bearer') {
    const enrolled = newBearerCredential({ id: PROBE_ID, scopes: ALL_GRANTS, now: NOW_SECONDS });
    return {
      state,
      record: { ...enrolled.record, rate: { perMinute: 60, burst: 8 } },
      ownKey: null,
      bearerSecret: enrolled.secret,
    };
  }
  const generated = newPopCredential({ id: PROBE_ID, scopes: ALL_GRANTS, now: NOW_SECONDS });
  const record: CredentialRecord = {
    ...generated.record,
    publicKey: RECORD_PUBLIC_KEY,
    rate: { perMinute: 60, burst: 8 },
    scopes: ALL_GRANTS,
    ...(state === 'revoked-pop' ? { revokedAt: NOW_SECONDS - 1 } : {}),
    ...(state === 'small-order-key' ? { publicKey: new Uint8Array(32) } : {}),
    ...(state === 'pop-with-secret-hash' ? { secretHash: new Uint8Array(32) } : {}),
  };
  const signable = state === 'live-pop' || state === 'revoked-pop';
  return { state, record, ownKey: signable ? RECORD_SEED : null, bearerSecret: UNENROLLED_SECRET };
}

/** The records that are not the probe: one proof of possession and one bearer key, present in both stores. */
function sharedRecords(): CredentialRecord[] {
  const pop: CredentialRecord = {
    ...newPopCredential({ id: SHARED_NAME, scopes: ALL_GRANTS, now: NOW_SECONDS }).record,
    publicKey: SHARED_PUBLIC_KEY,
    rate: { perMinute: 60, burst: 8 },
  };
  const bearer = newBearerCredential({ id: 'ops-shared', scopes: ALL_GRANTS, now: NOW_SECONDS });
  return [pop, { ...bearer.record, rate: { perMinute: 60, burst: 8 } }];
}

/** Two files that differ by one record, rebuilt per cell so no cell inherits another's replay set or bucket. */
function storesFor(probed: Probed): { holds: CredentialStore; lacks: CredentialStore } {
  const shared = sharedRecords();
  const now = () => CLOCK_MS;
  return {
    holds: new CredentialStore({ file: { version: 1, credentials: [...shared, probed.record] }, allowBearer: true, now }),
    lacks: new CredentialStore({ file: { version: 1, credentials: [...shared] }, allowBearer: true, now }),
  };
}

type NonceSpelling = 'present' | 'absent' | 'too-short' | 'not-base64url' | 'differs-from-signed';

function nonceHeaderFor(spelling: NonceSpelling, signed: Uint8Array): Record<string, string> {
  switch (spelling) {
    case 'present':
      return { 'x-ashaveri-nonce': toBase64Url(signed) };
    case 'differs-from-signed':
      return { 'x-ashaveri-nonce': toBase64Url(ANOTHER_NONCE) };
    case 'too-short':
      return { 'x-ashaveri-nonce': toBase64Url(signed.slice(0, POP_NONCE_BYTES - 1)) };
    case 'not-base64url':
      return { 'x-ashaveri-nonce': 'not base64url at all' };
    case 'absent':
      return {};
  }
}

function shapeInput(header: string, spelling: NonceSpelling, route: HttpRoute): AdmissionInput {
  return {
    method: route.method,
    url: route.url,
    headers: { authorization: header, ...nonceHeaderFor(spelling, SHAPE_NONCE) },
    body: null,
    nowSeconds: NOW_SECONDS,
  };
}

function signedHeader(key: Uint8Array, ts: number, route: HttpRoute, credential: string = PROBE_ID): string {
  return signPopAuthorization(
    { ts, nonce: SHAPE_NONCE, method: route.method.toUpperCase(), target: route.url, bodyDigestHex: EMPTY_BODY_SHA256_HEX },
    credential,
    key,
  );
}

interface Cell {
  readonly input: AdmissionInput;
  /** True when the test signed these bytes with the key the record carries, on a request well-formed enough to reach the checks behind the signature. */
  readonly proves: boolean;
}

interface Shape {
  readonly name: string;
  readonly make: (probed: Probed) => Cell;
}

/**
 * A proof-of-possession request naming `N`. Where the record carries no key the test can sign with, the
 * `record-key` shapes are signed with the foreign key instead, which is the same class of refusal from the
 * store's point of view and is marked as proving nothing.
 */
function popShape(name: string, signer: 'record-key' | 'foreign-key', stamp: Stamp, spelling: NonceSpelling, route: HttpRoute): Shape {
  return {
    name,
    make: (probed) => {
      const own = signer === 'record-key' ? probed.ownKey : null;
      const ts = stamp === 'stale' ? STALE_TS : NOW_SECONDS;
      return {
        input: shapeInput(signedHeader(own ?? FORGER_SEED, ts, route), spelling, route),
        proves: own !== null && stamp === 'fresh' && spelling === 'present',
      };
    },
  };
}

/** A header whose signature is bytes nobody signed, which is the shape a relaxed verifier accepts against a small-order key. */
function handWrittenShape(name: string, signature: Uint8Array, stamp: Stamp, spelling: NonceSpelling, route: HttpRoute): Shape {
  return {
    name,
    make: () => ({
      input: shapeInput(
        encodePopAuthorization({ credential: PROBE_ID, ts: stamp === 'stale' ? STALE_TS : NOW_SECONDS, signature }),
        spelling,
        route,
      ),
      proves: false,
    }),
  };
}

/** A header the store is asked to read but never reaches: the scheme or the parameter list is settled at the door. */
function doorShape(name: string, header: string | undefined): Shape {
  return {
    name,
    make: () => ({
      input: {
        method: WORK_ROUTE.method,
        url: WORK_ROUTE.url,
        headers: header === undefined ? {} : { authorization: header },
        body: null,
        nowSeconds: NOW_SECONDS,
      },
      proves: false,
    }),
  };
}

function bearerShape(name: string, secret: (probed: Probed) => Uint8Array, provesBearer: (probed: Probed) => boolean): Shape {
  return {
    name,
    make: (probed) => ({ input: bearerInput(WORK_ROUTE, secret(probed)), proves: provesBearer(probed) }),
  };
}

const SHAPES: readonly Shape[] = [
  popShape('record-key/fresh/nonce-present/work', 'record-key', 'fresh', 'present', WORK_ROUTE),
  popShape('record-key/fresh/nonce-present/unlisted', 'record-key', 'fresh', 'present', UNLISTED_ROUTE),
  popShape('record-key/fresh/nonce-present/complete', 'record-key', 'fresh', 'present', COMPLETE_ROUTE),
  popShape('record-key/fresh/nonce-differs-from-signed', 'record-key', 'fresh', 'differs-from-signed', WORK_ROUTE),
  popShape('record-key/stale/nonce-present', 'record-key', 'stale', 'present', WORK_ROUTE),
  popShape('record-key/fresh/nonce-absent', 'record-key', 'fresh', 'absent', WORK_ROUTE),
  popShape('record-key/fresh/nonce-too-short', 'record-key', 'fresh', 'too-short', WORK_ROUTE),
  popShape('record-key/fresh/nonce-not-base64url', 'record-key', 'fresh', 'not-base64url', WORK_ROUTE),
  popShape('foreign-key/fresh/nonce-present/work', 'foreign-key', 'fresh', 'present', WORK_ROUTE),
  popShape('foreign-key/stale/nonce-present/work', 'foreign-key', 'stale', 'present', WORK_ROUTE),
  popShape('foreign-key/fresh/nonce-absent/work', 'foreign-key', 'fresh', 'absent', WORK_ROUTE),
  popShape('foreign-key/fresh/nonce-present/unlisted', 'foreign-key', 'fresh', 'present', UNLISTED_ROUTE),
  popShape('foreign-key/fresh/nonce-present/complete', 'foreign-key', 'fresh', 'present', COMPLETE_ROUTE),
  handWrittenShape('unsigned/zero-signature/fresh/nonce-present/work', ZERO_SIGNATURE, 'fresh', 'present', WORK_ROUTE),
  handWrittenShape('unsigned/saturated-signature/fresh/nonce-present/work', SATURATED_SIGNATURE, 'fresh', 'present', WORK_ROUTE),
  handWrittenShape('unsigned/zero-signature/fresh/nonce-present/unlisted', ZERO_SIGNATURE, 'fresh', 'present', UNLISTED_ROUTE),
  handWrittenShape('unsigned/zero-signature/stale/nonce-present/work', ZERO_SIGNATURE, 'stale', 'present', WORK_ROUTE),
  doorShape('door/absent-header', undefined),
  doorShape('door/blank-header', '   '),
  doorShape('door/other-scheme', 'Basic dXNlcjpwYXNz'),
  doorShape('door/pop-with-no-parameters', 'Ashaveri-PoP'),
  doorShape('door/pop-with-unknown-parameter', `${signedHeader(FORGER_SEED, NOW_SECONDS, WORK_ROUTE)}, algo=ed25519`),
  doorShape('door/pop-with-short-signature', `Ashaveri-PoP credential=${PROBE_ID}, ts=${String(NOW_SECONDS)}, sig=${toBase64Url(new Uint8Array(8))}`),
  bearerShape('bearer/presents-the-probes-secret', (probed) => probed.bearerSecret, (probed) => probed.state === 'bearer'),
  bearerShape('bearer/presents-an-unenrolled-secret', () => UNENROLLED_SECRET, () => false),
];

/** What one store answered one request: the whole of what the caller can observe. */
interface Answer {
  readonly kind: 'admitted' | 'refused' | 'escaped';
  readonly code: string;
  readonly status: string;
  readonly message: string;
}

function answer(store: CredentialStore, input: AdmissionInput): Answer {
  try {
    const granted = store.admit(input);
    return { kind: 'admitted', code: 'SERVED', status: 'served', message: `served as ${granted.credentialId} for ${granted.scope} by ${granted.auth}` };
  } catch (err) {
    if (err instanceof AccessError) {
      return { kind: 'refused', code: err.code, status: String(err.status), message: err.message };
    }
    const text = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return { kind: 'escaped', code: 'ESCAPED', status: 'threw', message: text };
  }
}

function show(a: Answer): string {
  return `${a.code} ${a.status} "${a.message}"`;
}

function identical(a: Answer, b: Answer): boolean {
  return a.code === b.code && a.status === b.status && a.message === b.message;
}

/** A request naming a record both files hold, which has to be served by both or the walk is not reaching a store. */
function controlRequest(): AdmissionInput {
  return shapeInput(signedHeader(SHARED_SEED, NOW_SECONDS, WORK_ROUTE, SHARED_NAME), 'present', WORK_ROUTE);
}

describe('two stores that differ only in whether they hold one name', () => {
  it('answers every request shape the same way and serves neither store', { timeout: 120_000 }, () => {
    const printed = process.env['TWO_STORE_MATRIX'] !== undefined;
    const lines: string[] = [];
    const failures: string[] = [];
    const tally = new Map<string, number>();
    let cells = 0;
    let proofCarrying = 0;

    for (const state of PROBED_STATES) {
      const probed = probedAs(state);
      const premise = storesFor(probed);
      expect(probed.record.id, `the probe record is the name the walk is about: ${state}`).toBe(PROBE_ID);
      expect(
        premise.holds.credentials().some((each) => each.id === PROBE_ID),
        `one store has to hold ${PROBE_ID}`,
      ).toBe(true);
      expect(
        premise.lacks.credentials().some((each) => each.id === PROBE_ID),
        `the other store has to hold nothing named ${PROBE_ID}`,
      ).toBe(false);
      expect(premise.holds.credentials()).toHaveLength(premise.lacks.credentials().length + 1);

      const controlHolds = answer(premise.holds, controlRequest());
      const controlLacks = answer(premise.lacks, controlRequest());
      expect(controlHolds.kind, `the control request naming a record both stores hold was not served: ${show(controlHolds)}`).toBe('admitted');
      expect(controlLacks.kind, `the same control was not served by the store without the probe: ${show(controlLacks)}`).toBe('admitted');
      expect(identical(controlHolds, controlLacks), `the control has to read the same in both: ${show(controlHolds)} / ${show(controlLacks)}`).toBe(true);

      for (const shape of SHAPES) {
        cells += 1;
        const { input, proves } = shape.make(probed);
        if (proves) proofCarrying += 1;
        const stores = storesFor(probed);
        const holds = answer(stores.holds, input);
        const lacks = answer(stores.lacks, input);
        const where = `${state} x ${shape.name}${proves ? ' [proves]' : ''}`;
        if (printed) lines.push(`${where.padEnd(58)} holds ${show(holds)} | lacks ${show(lacks)}`);

        if (lacks.kind === 'admitted') {
          failures.push(`${where}: the store holding nothing named ${PROBE_ID} served the request: ${show(lacks)}`);
        }
        if (proves) continue;
        if (holds.kind === 'admitted') {
          failures.push(`${where}: the store holding a ${state} record served a request that proves nothing: ${show(holds)}`);
        }
        if (identical(holds, lacks)) continue;
        const pair = `${holds.code}/${holds.status} vs ${lacks.code}/${lacks.status}`;
        tally.set(pair, (tally.get(pair) ?? 0) + 1);
        failures.push(`${where}: the name is answered differently\n    holds N: ${show(holds)}\n    lacks N: ${show(lacks)}`);
      }
    }

    const grouped = [...tally.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([pair, count]) => `  ${String(count).padStart(3)} cells: ${pair}`);
    process.stdout.write(
      `two-store: ${String(cells)} cells over ${String(PROBED_STATES.length)} records and ${String(SHAPES.length)} shapes, ` +
        `${String(proofCarrying)} proof-carrying, ${String(tally.size)} answer pairs diverge, ${String(failures.length)} failures\n` +
        `${grouped.join('\n')}\n`,
    );
    if (printed) process.stdout.write(`${lines.join('\n')}\n`);
    if (failures.length > 0) process.stdout.write(`${failures.join('\n')}\n`);
    expect(failures.length, `the two stores answered differently, or one of them served a request:\n${failures.slice(0, 12).join('\n')}`).toBe(0);
  });
});

afterAll(() => {
  const seconds = ((performance.now() - STARTED_AT) / 1000).toFixed(2);
  process.stdout.write(
    `access-order: seed ${String(SEED)}, ${String(propertyCalls)} properties, ` +
      `${String(predicateCalls)} predicate calls, ${String(walkedRows)} walk rows, wall clock ${seconds}s\n`,
  );
});

