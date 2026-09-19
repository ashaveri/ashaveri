import { afterAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  AccessError,
  CredentialStore,
  newBearerCredential,
  parseCredentialFile,
  type AdmissionInput,
  type CredentialRecord,
} from '../src/access.js';
import { sha256, toHex } from '../src/digest.js';

/**
 * Properties over the two halves of bearer admission: the decode `admitBearer` performs on the header
 * text before it hashes anything (`gateway/src/access.ts`), and the compare loop `constantTimeEquals`
 * that the scan uses to decide which stored digest the header names.
 *
 * Both questions are asked against `CredentialStore.admit` directly, with no server and no socket, which
 * is also how `admission.test.ts` drives the bearer branch. Reaching the loop that way has one
 * consequence worth stating before any assertion does: its only call sits beside
 * `bearerSecretHashOf`, which drops every record whose stored digest is not 32 bytes, and the
 * presented side is a SHA-256 output and so is always 32 bytes. Every comparison this surface can build
 * is 32 against 32, so the loop's length guard never sees unequal operands and no gate here can pin it.
 * The zero-length pair is unreachable for the same reason: an empty stored digest is dropped by the
 * width filter before the loop, and an empty *presented* secret is refused by `bearerSecret`'s header
 * rule before the digest is taken. What is pinned instead is that the answer agrees with byte equality
 * over the pairs the surface can build, one differing bit at a time, and that a stored digest of any
 * other width is never the answer.
 *
 * This is a correctness property, not a timing measurement. It says which answer the loop returns;
 * nothing in this file can observe whether it returns early, and no gate here should be read as a
 * side-channel test.
 */

/** Set from the environment so a red run replays exactly: `FC_SEED=1234` on the package's test run. */
const SEED = Number(process.env['FC_SEED'] ?? '20260918');

/** Kept low enough that the file runs in seconds. The stores below, not this number, carry the coverage. */
const RUNS = Number(process.env['FC_RUNS'] ?? '300');

const STARTED_AT = performance.now();
let propertyCalls = 0;
let predicateCalls = 0;

/**
 * `fc.assert` fires the predicate `runs` times in total and the pinned examples are drawn from inside
 * that budget, so this counter is the call count rather than calls plus examples.
 */
function check<T>(
  arbitrary: fc.Arbitrary<T>,
  examples: readonly T[],
  predicate: (value: T) => boolean,
  runs: number = RUNS,
): void {
  propertyCalls += 1;
  predicateCalls += runs;
  fc.assert(fc.property(arbitrary, predicate), {
    numRuns: runs,
    seed: SEED,
    examples: examples.map((each) => [each] as [T]),
  });
}

const CLOCK_SECONDS = 1_772_000_000;
const CLOCK_MS = CLOCK_SECONDS * 1000;

/**
 * A bearer admission spends a token, and a sweep admits on one credential hundreds of times, so every
 * fixture record gets a budget the sweep cannot exhaust. A refusal spends nothing, which is why the
 * refusing gates need no rate at all.
 */
const SWEEP_RATE = { perMinute: 1_000_000, burst: 1_000_000 };

/** `GET /v1/deployment-manifest` is scoped `any`, so the scope check never answers before the digest does. */
function bearerRequest(header: string): AdmissionInput {
  return { method: 'GET', url: '/v1/deployment-manifest', headers: { authorization: header }, body: null };
}

/** Node's lenient decoder, spelled the way the store spells it. */
function decode(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

/** The canonical unpadded spelling of some bytes, which is the shortest text that decodes to them. */
function spell(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let at = 0; at < left.length; at++) {
    if (left[at] !== right[at]) return false;
  }
  return true;
}

/** How many positions two equal-width byte strings differ in, which is what makes a stimulus minimal. */
function differingPositions(left: Uint8Array, right: Uint8Array): number[] {
  const out: number[] = [];
  const width = Math.min(left.length, right.length);
  for (let at = 0; at < width; at++) {
    if (left[at] !== right[at]) out.push(at);
  }
  return out;
}

/** Derived rather than random, so a red run replays from `FC_SEED` alone. */
function preimage(tag: string): Uint8Array {
  return sha256(new TextEncoder().encode(tag));
}

function bearerRecord(id: string, digest: Uint8Array, extra: Partial<CredentialRecord> = {}): CredentialRecord {
  return {
    id,
    kind: 'bearer',
    secretHash: digest,
    scopes: ['read', 'complete'],
    createdAt: CLOCK_SECONDS,
    rate: SWEEP_RATE,
    ...extra,
  };
}

/**
 * One construction site for every store in this file, built outside every predicate: a bearer-capable
 * deployment on a frozen clock, so no bucket refills while a sweep is counting it.
 */
function makeStore(credentials: readonly CredentialRecord[]): CredentialStore {
  return new CredentialStore({
    file: { version: 1, credentials: [...credentials] },
    allowBearer: true,
    now: () => CLOCK_MS,
  });
}

/** The whole answer, in one string: which credential was admitted, or which code refused it. */
function answerHeader(store: CredentialStore, header: string): string {
  try {
    return `admit:${store.admit(bearerRequest(header)).credentialId}`;
  } catch (err) {
    if (err instanceof AccessError) return `refuse:${err.code}`;
    throw err;
  }
}

/** The same answer for a header made of the `Bearer ` prefix and this text. */
function answer(store: CredentialStore, text: string): string {
  return answerHeader(store, `Bearer ${text}`);
}

/** The prose a refusal hands back, so two refusals can be compared beyond their code. */
function refusalText(store: CredentialStore, text: string): string {
  try {
    store.admit(bearerRequest(`Bearer ${text}`));
    return 'admitted';
  } catch (err) {
    if (err instanceof AccessError) return `${err.code} ${err.detail ?? ''}`.trim();
    throw err;
  }
}

// --- the store the decode questions are asked against -------------------------------------------

const SECRET_COUNT = 6;
const STORE_SECRETS: Uint8Array[] = [];
const STORE_RECORDS: CredentialRecord[] = [];
for (let at = 0; at < SECRET_COUNT; at++) {
  const secret = preimage(`bearer-decode-secret-${String(at)}`);
  STORE_SECRETS.push(secret);
  STORE_RECORDS.push(bearerRecord(`ops-${String(at)}`, sha256(secret)));
}
const STORE = makeStore(STORE_RECORDS);

/** The answer the bytes oblige: the record whose secret *is* these bytes, else the wrong-secret refusal. */
function recordFor(decoded: Uint8Array): string {
  for (let at = 0; at < STORE_SECRETS.length; at++) {
    const secret = STORE_SECRETS[at];
    if (secret !== undefined && sameBytes(secret, decoded)) return `admit:ops-${String(at)}`;
  }
  return 'refuse:AUTH_UNKNOWN';
}

// --- texts, and the respellings of them that Node maps to the same bytes ------------------------

/** The 64 characters a canonical spelling is made of. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** Out of the alphabet, so the decoder drops them: no `=`, which ends the data, and no `+` or `/`, which it accepts as aliases. */
const DROPPED = '!@#$%^&*()[]{}<>?;,.~`|';
const CHARACTERS = `${ALPHABET}+/=${DROPPED}`;

/** A text made of `min` to `max` characters drawn from one alphabet. */
function chars(letters: string, min: number, max: number): fc.Arbitrary<string> {
  return fc
    .array(fc.constantFrom(...letters.split('')), { minLength: min, maxLength: max })
    .map((picked) => picked.join(''));
}

const arbBytes = fc
  .array(fc.integer({ min: 0, max: 255 }), { minLength: 1, maxLength: 40 })
  .map((parts) => Uint8Array.from(parts));

const arbText = fc.oneof(
  fc.integer({ min: 0, max: SECRET_COUNT - 1 }).map((at) => spell(STORE_SECRETS[at] ?? new Uint8Array(0))),
  chars(DROPPED, 1, 9),
  chars(CHARACTERS, 1, 64),
  arbBytes.map((bytes) => spell(bytes)),
);

/** A stored secret plus text the decoder drops, plus padding: one class, several spellings. */
const arbRespelling = fc.tuple(
  arbText,
  chars(DROPPED, 1, 6),
  fc.integer({ min: 0, max: 3 }),
);

describe('the bearer decode is a function of bytes, not of spelling', () => {
  it('answers every text with the record its decoded bytes name, and nothing else', () => {
    check(
      arbText,
      [
        spell(STORE_SECRETS[0] ?? new Uint8Array(0)),
        'AAAA####',
        '!!!!',
        'q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s',
      ],
      (text) => {
        const got = answer(STORE, text);
        const expected = recordFor(decode(text));
        return got === expected;
      },
    );
  });

  it('gives one answer to every spelling of one byte string, including the spellings no generator would emit', () => {
    check(arbRespelling, [['AAAA', '####', 0], ['AB', '~~~', 1], [spell(STORE_SECRETS[1] ?? new Uint8Array(0)), '@@', 2]] as [string, string, number][], ([text, junk, pads]) => {
      const respelled = `${text}${junk}${'='.repeat(pads)}`;
      // The premise, asserted rather than assumed: this respelling family is the one the decoder drops.
      if (!sameBytes(decode(text), decode(respelled))) return false;
      return answer(STORE, text) === answer(STORE, respelled);
    });
  });

  it('equals the canonical spelling of its own decode, whenever that spelling is a bearer secret at all', () => {
    check(
      arbText.filter((text) => decode(text).length > 0),
      ['AAAA####', 'aZ09-_!!'],
      (text) => {
        const canonical = spell(decode(text));
        return answer(STORE, text) === answer(STORE, canonical);
      },
    );
  });

  it('refuses a text that decodes to bytes no record holds, with the code a wrong secret gets', () => {
    const wrongSecret = spell(preimage('bearer-decode-never-enrolled'));
    expect(answer(STORE, wrongSecret)).toBe('refuse:AUTH_UNKNOWN');
    expect(answer(STORE, '!!!!')).toBe('refuse:AUTH_UNKNOWN');
    expect(answer(STORE, '####')).toBe('refuse:AUTH_UNKNOWN');
    // Same code and the same sentence: the refusal cannot be used to tell a garbage text from a wrong secret.
    expect(refusalText(STORE, '!!!!')).toBe(refusalText(STORE, wrongSecret));
    expect(refusalText(STORE, '####')).toBe(refusalText(STORE, 'AAAA####'));
  });

  it('keeps a header that is not a bearer header out of the digest scan', () => {
    for (const header of ['Bearer    ', 'Bearer \t', 'Bearer ', 'bearer', 'Basic dXNlcjpwYXNz', 'bearer short']) {
      // The whole header is trimmed before the prefix is read, so a bearer token of nothing at all leaves no
      // prefix standing and the scheme check answers. So does any header naming another scheme.
      expect(answerHeader(STORE, header)).toBe('refuse:AUTH_SCHEME');
    }
    for (const header of ['Ashaveri-PoP credential=ops-0', 'Ashaveri-PoP']) {
      const got = answerHeader(STORE, header);
      // Whatever the PoP parser makes of a header naming its own scheme badly, it is not the bearer scan's
      // answer, and the scan's answer is the one this file is about.
      expect(got.startsWith('admit:')).toBe(false);
      expect(got).not.toBe('refuse:AUTH_UNKNOWN');
    }
  });
});

// --- the digest of nothing, which the file parser refuses ---------------------------------------

/** `sha256` over no bytes at all: 64 lower-case hex characters, so the width rule alone accepted it. */
const NOTHING_DIGEST_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const NOTHING_DIGEST = sha256(new Uint8Array(0));

function handWrittenCredentialFile(withNothingRecord: boolean): string {
  const enrolled = [
    {
      id: 'ops-0',
      kind: 'bearer',
      secretHash: toHex(sha256(STORE_SECRETS[0] ?? new Uint8Array(0))),
      scopes: ['read', 'complete'],
      createdAt: CLOCK_SECONDS,
      rate: SWEEP_RATE,
    },
  ];
  if (withNothingRecord) {
    enrolled.unshift({
      id: 'no-secret',
      kind: 'bearer',
      secretHash: NOTHING_DIGEST_HEX,
      scopes: ['read', 'complete'],
      createdAt: CLOCK_SECONDS,
      rate: SWEEP_RATE,
    });
  }
  return `${JSON.stringify({ version: 1, credentials: enrolled })}\n`;
}

function refuseCodeOf(text: string): string {
  try {
    parseCredentialFile(text);
    return 'accepted';
  } catch (err) {
    return err instanceof AccessError ? `refuse:${err.code}` : 'threw';
  }
}

/** The sentence a refusal carries, which is the only way to tell which of two rules fired. */
function refuseDetailOf(text: string): string {
  try {
    parseCredentialFile(text);
    return 'accepted';
  } catch (err) {
    return err instanceof AccessError ? (err.detail ?? '') : 'threw';
  }
}

/**
 * The record the parser refuses, handed to the store the way a caller that builds records in memory
 * hands over any other: `bearerSecretHashOf` polices a digest's width and nothing about its entropy,
 * so the scan answers these bytes to a text that decodes to nothing.
 */
const NOTHING_STORE = makeStore([
  bearerRecord('no-secret', NOTHING_DIGEST),
  bearerRecord('ops-0', sha256(STORE_SECRETS[0] ?? new Uint8Array(0))),
]);

describe('the digest of nothing: refused as a file, and a secret anyone can present when it is not', () => {
  it('refuses a hand-written `secretHash` that is the digest of no bytes, and loads the file without it', () => {
    // The rule that let it through was about hex, not about entropy: 64 lower-case characters is a
    // well-formed digest of a real message, namely of nothing. `parseRecord` now names it.
    expect(toHex(NOTHING_DIGEST)).toBe(NOTHING_DIGEST_HEX);
    expect(refuseCodeOf(handWrittenCredentialFile(true))).toBe('refuse:BAD_CREDENTIAL_RECORD');
    // The code alone would not tell this rule from the width rule above it, and the two are only
    // separable by their sentence: a file whose hash is upper-case hex is refused for its shape.
    expect(refuseDetailOf(handWrittenCredentialFile(true))).toContain('digest of no bytes');
    expect(parseCredentialFile(handWrittenCredentialFile(false)).credentials.map((record) => record.id)).toEqual([
      'ops-0',
    ]);
  });

  it('admits a bearer header of punctuation as that record, while the same header is refused elsewhere', () => {
    for (const text of ['!!!!', '####', '????????', '{}{}{}', ';;', '@@@@@@@@']) {
      expect(answer(NOTHING_STORE, text)).toBe('admit:no-secret');
    }
    // Every one of those texts decodes to zero bytes, so they are one equivalence class, and the class
    // has a record in it. Without the record the same class answers as a wrong secret does.
    for (const text of ['!!!!', '####', '????????']) {
      expect(decode(text).length).toBe(0);
      expect(answer(STORE, text)).toBe('refuse:AUTH_UNKNOWN');
    }
  });

  it('answers a punctuation secret and a genuine secret with two admissions that differ only by name', () => {
    const garbage = NOTHING_STORE.admit(bearerRequest('Bearer !!!!'));
    const genuine = NOTHING_STORE.admit(bearerRequest(`Bearer ${spell(STORE_SECRETS[0] ?? new Uint8Array(0))}`));
    expect(garbage.credentialId).toBe('no-secret');
    expect(genuine.credentialId).toBe('ops-0');
    // Same shape, same auth label, no nonce on either: the credential named, and so the bucket charged and
    // the id in the access record, is the only thing a caller of `admit` can tell apart.
    expect({ ...garbage, credentialId: 'shared' }).toEqual({ ...genuine, credentialId: 'shared' });
  });

  it('has no canonical member of the nothing class that a bearer secret can be, and admits the in-alphabet members', () => {
    // The canonical spelling of no bytes is the empty text, and `admit` trims the header before the
    // prefix is looked for, so `Bearer ` has no token left to hash: `bearerSecret` answers nothing, and
    // the AUTH_SCHEME comes from `parseAuthorization`. What the class does hold is every text shorter
    // than one byte of bits, and two of those are characters a canonical spelling is made of, so this
    // secret needs no punctuation to present at all.
    expect(decode('').length).toBe(0);
    expect(answer(NOTHING_STORE, '')).toBe('refuse:AUTH_SCHEME');
    expect(answer(NOTHING_STORE, '!!!!')).toBe('admit:no-secret');
    for (const text of ['-', '_']) {
      expect(ALPHABET).toContain(text);
      expect(decode(text).length).toBe(0);
      expect(answer(NOTHING_STORE, text)).toBe('admit:no-secret');
      expect(answer(STORE, text)).toBe('refuse:AUTH_UNKNOWN');
    }
  });

  it('cannot be enrolled by the generator, which draws 32 random bytes', () => {
    const made = newBearerCredential({ id: 'generated', now: CLOCK_SECONDS });
    expect(made.secret.length).toBe(32);
    expect(toHex(made.record.secretHash ?? new Uint8Array(0))).not.toBe(NOTHING_DIGEST_HEX);
  });

  it('refuses a `secretHash` that is not 64 lower-case hex characters', () => {
    const fileWith = (hash: string): string =>
      `{"version":1,"credentials":[{"id":"x","kind":"bearer","secretHash":"${hash}","scopes":["read"],"createdAt":${String(CLOCK_SECONDS)}}]}`;
    expect(refuseCodeOf(fileWith(NOTHING_DIGEST_HEX.toUpperCase()))).toBe('refuse:BAD_CREDENTIAL_RECORD');
    expect(refuseCodeOf(fileWith(NOTHING_DIGEST_HEX.slice(1)))).toBe('refuse:BAD_CREDENTIAL_RECORD');
    expect(refuseCodeOf(fileWith(`${NOTHING_DIGEST_HEX}00`))).toBe('refuse:BAD_CREDENTIAL_RECORD');
    expect(refuseCodeOf(fileWith(NOTHING_DIGEST_HEX.replace('e', 'z')))).toBe('refuse:BAD_CREDENTIAL_RECORD');
  });
});

// --- the compare loop, reached through the bearer branch only -----------------------------------

const TRUE_ID = 'digest-under-test';
const TARGET_SECRET = preimage('bearer-decode-presented');
const TARGET_DIGEST = sha256(TARGET_SECRET);

interface Decoy {
  readonly id: string;
  readonly digest: Uint8Array;
  readonly at: number;
  readonly bit: number;
}

/**
 * One decoy per byte index and bit, each a single bit away from the digest the store will be asked
 * about, and every one of them ahead of the true record in the scan order. A loop that ignores a
 * position therefore answers with a decoy's id rather than failing to answer, which is what makes a
 * one-bit difference at that position observable.
 */
const DECOYS: Decoy[] = [];
for (let at = 0; at < 32; at++) {
  for (let bit = 0; bit < 8; bit++) {
    const digest = Uint8Array.from(TARGET_DIGEST, (byte) => byte);
    digest[at] = (digest[at] ?? 0) ^ (1 << bit);
    DECOYS.push({ id: `decoy-${String(at)}-${String(bit)}`, digest, at, bit });
  }
}
const COMPARE_STORE = makeStore([...DECOYS.map((decoy) => bearerRecord(decoy.id, decoy.digest)), bearerRecord(TRUE_ID, TARGET_DIGEST)]);
const PRESENTED = spell(TARGET_SECRET);

/** The same digest with one byte hung off it, or cut short, at each width the parser could be handed. */
function digestOfWidth(width: number): Uint8Array {
  if (width <= 32) return TARGET_DIGEST.subarray(0, width);
  const wider = new Uint8Array(width);
  wider.set(TARGET_DIGEST, 0);
  return wider;
}

const WIDTHS = [0, 1, 31, 33, 64];
const WIDTH_STORES = new Map<number, CredentialStore>();
for (const width of WIDTHS) {
  WIDTH_STORES.set(width, makeStore([bearerRecord(`width-${String(width)}`, digestOfWidth(width)), bearerRecord(TRUE_ID, TARGET_DIGEST)]));
}

describe('the compare loop answers byte equality, over the pairs the bearer branch can build', () => {
  it('refuses a stored digest that differs from the presented one in a single bit, at every index and bit', () => {
    check(
      fc.constantFrom(...DECOYS),
      [],
      (decoy) => {
        // The stimulus, asserted: this pair differs from the presented digest in exactly one position.
        if (decoy.digest.length !== TARGET_DIGEST.length) return false;
        if (differingPositions(decoy.digest, TARGET_DIGEST).length !== 1) return false;
        if (differingPositions(decoy.digest, TARGET_DIGEST)[0] !== decoy.at) return false;
        // And the loop's answer: the decoy is refused, so the scan walks past it to the record that matches.
        return answer(COMPARE_STORE, PRESENTED) === `admit:${TRUE_ID}`;
      },
    );
  });

  it('admits the pair that is equal, from the same scan, and reports that record and no other', () => {
    expect(answer(COMPARE_STORE, PRESENTED)).toBe(`admit:${TRUE_ID}`);
    check(
      fc.record({ at: fc.integer({ min: 0, max: 31 }), bit: fc.integer({ min: 0, max: 7 }), extra: fc.integer({ min: 1, max: 40 }) }),
      [],
      (drawn) => {
        // A secret that is not the enrolled one is refused, whatever length it decodes to, and the answer
        // is the same sentence the garbage texts get.
        const bytes = Uint8Array.from({ length: drawn.extra }, (_, i) => (TARGET_SECRET[i] ?? 0) ^ ((drawn.at + i) % 251));
        const other = spell(bytes);
        return (
          answer(COMPARE_STORE, other) === 'refuse:AUTH_UNKNOWN' &&
          refusalText(COMPARE_STORE, other) === refusalText(COMPARE_STORE, '!!!!')
        );
      },
    );
  });

  it('never answers with a stored digest whose width is not 32 bytes, whatever width that digest is', () => {
    check(
      fc.tuple(fc.constantFrom(...WIDTHS), fc.oneof(arbText, fc.constant(PRESENTED))),
      [],
      ([width, text]) => {
        const store = WIDTH_STORES.get(width);
        if (store === undefined) return false;
        // The odd-width record is the presented digest truncated or padded, so it agrees with the wanted
        // bytes as far as it goes and only its length can refuse it. The true record, which is 32 bytes and
        // follows it in the scan, is the only admissible answer for the enrolled secret.
        const expected = sameBytes(decode(text), TARGET_SECRET) ? `admit:${TRUE_ID}` : 'refuse:AUTH_UNKNOWN';
        return answer(store, text) === expected;
      },
    );
  });

  it('skips a revoked record whose digest the presented secret matches exactly', () => {
    const live = makeStore([bearerRecord('revoked-only', TARGET_DIGEST)]);
    expect(answer(live, PRESENTED)).toBe('admit:revoked-only');
    const revoked = makeStore([bearerRecord('revoked-only', TARGET_DIGEST, { revokedAt: CLOCK_SECONDS - 60 })]);
    expect(answer(revoked, PRESENTED)).toBe('refuse:AUTH_UNKNOWN');
  });
});

afterAll(() => {
  const seconds = ((performance.now() - STARTED_AT) / 1000).toFixed(1);
  process.stdout.write(
    `bearer-decode: seed ${String(SEED)}, ${String(propertyCalls)} properties, ` +
      `${String(predicateCalls)} predicate calls, ${String(DECOYS.length)} digest decoys, wall clock ${seconds}s\n`,
  );
});
