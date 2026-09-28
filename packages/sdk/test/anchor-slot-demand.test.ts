import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { Ajv2020 } from 'ajv/dist/2020.js';
import {
  hashRequest,
  issueReceipt,
  signingKeyFromSeed,
  type CollateralValidityAnchor,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import {
  MAX_ANCHOR_SLOTS_DEMANDABLE,
  SdkError,
  loadPolicyFromText,
  parsePolicyFile,
  policyFileDigest,
  policyFileFromPolicy,
  policyFileToJson,
  policyKeyByKid,
  toBase64Url,
  toHex,
  verifyCompletionReceipt,
  type AshaveriPolicy,
  type PolicyFile,
} from '../src/index.js';

/**
 * The demand a policy can make about an anchor, and the refusal it reaches.
 *
 * Two routes are under test, because a demand travels two ways: the document an operator writes, and the
 * receipt a client checks under what that document says. The first group is the loader's, and it is where a
 * number no policy can carry is refused rather than read. The second is `verifyCompletionReceipt`'s, because
 * that is the code a deployment's artifact is handed to, so every verdict below is reached through it and
 * not through the comparison function beside it, which a caller could call wrongly and this file would never
 * notice.
 *
 * The property the last block is arranged around is that a policy naming nothing changes no verdict. It is
 * proved by pinning each verdict as a string, and not by comparing two calls and watching them agree: a guard
 * that fired on an absent demand would refuse both of two otherwise identical calls, the two would match, and
 * the file would be green over a posture that had moved.
 */

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(11));
const OTHER_KEY = signingKeyFromSeed(new Uint8Array(32).fill(12));
const KID = toHex(KEY.kid);
const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(3);
const REQUEST_HASH = new Uint8Array(32).fill(4);
const EMPTY = new Uint8Array(0);
const RESPONSE_HASH = hashRequest(EMPTY);
const MEASUREMENT = new Uint8Array(48).fill(6);

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** The slot shapes, named by what each states rather than by a number. */
const held = (label: string) => ({ presence: 'held' as const, sha256: hashRequest(utf8(label)) });
const absent = (reason: string) => ({ presence: 'absent-at-source' as const, reason });
const notTakenIn = (reason: string) => ({ presence: 'not-taken-in' as const, reason });

const CHAIN_GAP = 'the source published no window for this level';
const COLLATERAL_GAP = 'the source published no chain for this chip';
const COLLECTOR_GAP = 'this issuer records no validity context at issuance';
const NOTHING_TAKEN = 'this issuer takes no collateral into the record it signs with';

const ANCHORS: Record<string, CollateralValidityAnchor> = {
  'both held': { collateral: held('collateral bytes'), validity: held('validity bytes') },
  'collateral held, validity absent at source': {
    collateral: held('collateral bytes'),
    validity: absent(CHAIN_GAP),
  },
  'collateral absent at source, validity held': {
    collateral: absent(COLLATERAL_GAP),
    validity: held('validity bytes'),
  },
  'collateral held, validity never taken in': {
    collateral: held('collateral bytes'),
    validity: notTakenIn(COLLECTOR_GAP),
  },
  'both never taken in': {
    collateral: notTakenIn(NOTHING_TAKEN),
    validity: notTakenIn(COLLECTOR_GAP),
  },
  'both absent at source': {
    collateral: absent(COLLATERAL_GAP),
    validity: absent(CHAIN_GAP),
  },
};

/**
 * One payload, at one version. `res` is the digest of no bytes because the client below is handed no bytes:
 * the marking claimed here is `sch: none`, whose region is the empty input by the format's own rule, so the
 * response checks hold and the only question left open is the anchor's.
 */
function payloadOver(version: 1 | 2 | 3, cva?: CollateralValidityAnchor): ReceiptPayload {
  const shared = {
    iss: 'dpl-9f2a41c3',
    ins: 'cvm-i-047f2a',
    iat: IAT,
    nce: NONCE,
    req: REQUEST_HASH,
    res: RESPONSE_HASH,
    mdl: 'mock-model-1',
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'snp' as const, m: MEASUREMENT },
    att: { d: new Uint8Array(32).fill(9), ts: IAT - 60, url: 'https://inference.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
  if (version === 1) return { v: 1, ...shared };
  const mk = { sch: 'none' as const, d: RESPONSE_HASH };
  if (version === 2) return { v: 2, ...shared, mk };
  if (cva === undefined) throw new Error('a v3 payload is built with the anchor it states');
  return {
    v: 3,
    ...shared,
    mk,
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva,
    itm: [{ t: IAT - 1, d: hashRequest(utf8('the one item of a buffered body')) }],
  };
}

function receiptOver(version: 1 | 2 | 3, cva?: CollateralValidityAnchor, by = KEY): Uint8Array {
  return issueReceipt(payloadOver(version, cva), by);
}

/**
 * One receipt handed to the shipped client path, answered with the string the tables below state. With no
 * policy the two clocks run nowhere; with one they run at their shipped defaults, and every receipt here is
 * stamped at the instant the call reads as now, so no verdict below is a window's. The response bytes are
 * the ones the receipt digests unless a case names others beside them, which is how a marked document is
 * handed the body it does not attest.
 */
function verdict(
  receiptBytes: Uint8Array,
  policy: AshaveriPolicy | undefined,
  responseBytes: Uint8Array = EMPTY,
): string {
  try {
    verifyCompletionReceipt({
      receiptBytes,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes,
      verifyKey: KEY.publicKey,
      ...(policy === undefined ? {} : { policy }),
      now: IAT * 1000,
    });
    return 'verify-ok';
  } catch (err) {
    if (err instanceof SdkError) return err.code;
    const code = (err as { code?: string })?.code;
    return typeof code === 'string' ? `receipt:${code}` : `unexpected:${String(err)}`;
  }
}

/** The message a refusal carried, or the empty string where the call answered instead. */
function messageOf(receiptBytes: Uint8Array, policy: AshaveriPolicy): string {
  try {
    verifyCompletionReceipt({
      receiptBytes,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: EMPTY,
      verifyKey: KEY.publicKey,
      policy,
      now: IAT * 1000,
    });
    return '';
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

/** A policy that pins one thing and names no anchor demand, and one that names the demand. */
const NO_DEMAND: AshaveriPolicy = { issuers: ['dpl-9f2a41c3'] };
const demandOf = (slots: number): AshaveriPolicy => ({ issuers: ['dpl-9f2a41c3'], minAnchorSlotsHeld: slots });

const docWith = (over: Record<string, unknown>): string =>
  JSON.stringify({ v: 1, issuers: ['dpl-9f2a41c3'], instances: ['cvm-i-047f2a'], ...over });

function loaderError(document: string): unknown {
  try {
    parsePolicyFile(document);
    return null;
  } catch (cause) {
    return cause;
  }
}

function loaderAccepts(document: Record<string, unknown>): boolean {
  return loaderError(JSON.stringify(document)) === null;
}

// ---------------------------------------------------------------------------
// The document, read.
// ---------------------------------------------------------------------------

describe('a policy document demanding an anchor', () => {
  it('reads the demand into the policy it names', async () => {
    const two = await loadPolicyFromText(docWith({ minAnchorSlotsHeld: 2 }), '.');
    expect(two.file.minAnchorSlotsHeld).toBe(2);
    expect(two.policy.minAnchorSlotsHeld).toBe(2);
    const one = await loadPolicyFromText(docWith({ minAnchorSlotsHeld: 1 }), '.');
    expect(one.policy.minAnchorSlotsHeld).toBe(1);
    expect(one.digest).not.toBe(two.digest);
  });

  it('reads an absent field and an explicit null as one policy that demands nothing', async () => {
    const absentField = await loadPolicyFromText(docWith({}), '.');
    const explicitNull = await loadPolicyFromText(docWith({ minAnchorSlotsHeld: null }), '.');
    expect(absentField.file.minAnchorSlotsHeld).toBeNull();
    expect(explicitNull.file.minAnchorSlotsHeld).toBeNull();
    expect(absentField.policy.minAnchorSlotsHeld).toBeUndefined();
    expect(explicitNull.policy.minAnchorSlotsHeld).toBeUndefined();
    expect(explicitNull.digest).toBe(absentField.digest);
  });

  it('carries one definition through the file, the object, the text and the digest', () => {
    const file: PolicyFile = parsePolicyFile(docWith({ minAnchorSlotsHeld: 1 }));
    expect(file.minAnchorSlotsHeld).toBe(1);
    const written = policyFileToJson(file);
    expect(JSON.parse(written).minAnchorSlotsHeld).toBe(1);
    expect(policyFileDigest(parsePolicyFile(written))).toBe(policyFileDigest(file));
    const fromObject = policyFileFromPolicy({ issuers: ['dpl-9f2a41c3'], instances: ['cvm-i-047f2a'], minAnchorSlotsHeld: 1 });
    expect(fromObject).toEqual(file);
    expect(policyFileDigest(fromObject)).toBe(policyFileDigest(file));
  });
});

describe('the loader refuses a demand no policy can carry', () => {
  const refused: Array<[label: string, value: unknown, because: string]> = [
    ['zero slots', 0, 'which no document can answer'],
    ['a negative count', -1, 'which no document can answer'],
    ['more slots than an anchor states', MAX_ANCHOR_SLOTS_DEMANDABLE + 1, 'which no document can answer'],
    ['a fraction of a slot', 1.5, 'must be a whole number of slots'],
    ['a string', '1', 'must be a whole number of slots'],
    ['a boolean', true, 'must be a whole number of slots'],
    ['an object', {}, 'must be a whole number of slots'],
    ['a list', [1], 'must be a whole number of slots'],
    ['a number past the point an integer is exact', Number.MAX_SAFE_INTEGER + 2, 'must be a whole number of slots'],
  ];

  for (const [label, value, because] of refused) {
    it(`refuses ${label} and names the two roads open`, () => {
      const err = loaderError(docWith({ minAnchorSlotsHeld: value }));
      expect(err, `${label} read as a demand`).toBeInstanceOf(SdkError);
      expect((err as SdkError).code).toBe('POLICY_FILE_INVALID');
      const message = (err as SdkError).message;
      expect(message).toContain("'minAnchorSlotsHeld'");
      expect(message).toContain(because);
      // Both roads, in both refusals: state a demand an artifact can answer, or leave the field out. A
      // refusal with no road out of it is a message an operator reads and cannot act on.
      expect(message).toContain('leave the field out');
      expect(message).toContain(String(MAX_ANCHOR_SLOTS_DEMANDABLE));
    });
  }

  it('refuses the spelling a JSON document can carry and no reader can state', () => {
    // `1e400` is how a document writes infinity, and the two windows refuse it for the same reason: what
    // arrives is a number no comparison answers, and a policy that cannot be weighed is not a demand.
    const err = loaderError('{"v":1,"issuers":["a"],"minAnchorSlotsHeld":1e400}');
    expect(err).toBeInstanceOf(SdkError);
    expect((err as SdkError).message).toContain('must be a whole number of slots');
    expect((err as SdkError).message).toContain('leave the field out');
  });
});

describe('the writer refuses a demand the document cannot spell', () => {
  it('refuses an infinite or not-a-number demand rather than let it arrive as its own absence', () => {
    // The written form of both is `null`, and `null` is this format's spelling of a policy that asks nothing
    // of an anchor, so a demand an operator wrote would reach an auditor as the absence of one.
    for (const value of [Number.POSITIVE_INFINITY, Number.NaN]) {
      let err: unknown = null;
      try {
        policyFileFromPolicy({ issuers: ['a'], minAnchorSlotsHeld: value });
      } catch (cause) {
        err = cause;
      }
      expect(err, String(value)).toBeInstanceOf(SdkError);
      expect((err as SdkError).code).toBe('POLICY_FILE_INVALID');
      expect((err as SdkError).message).toContain('no policy document can carry as a demand');
      expect((err as SdkError).message).toContain('name no demand at all');
    }
  });

  it('refuses an out-of-range demand on the road through the document too', () => {
    expect(() => policyFileFromPolicy({ issuers: ['a'], minAnchorSlotsHeld: 0 })).toThrow(SdkError);
    expect(() => policyFileFromPolicy({ issuers: ['a'], minAnchorSlotsHeld: MAX_ANCHOR_SLOTS_DEMANDABLE + 1 })).toThrow(
      SdkError,
    );
  });

  it('writes the key only where a demand was stated', () => {
    expect(JSON.parse(policyFileToJson(policyFileFromPolicy({ issuers: ['a'] }))).minAnchorSlotsHeld).toBeUndefined();
    expect(
      JSON.parse(
        policyFileToJson(parsePolicyFile('{"v":1,"issuers":["a"],"minAnchorSlotsHeld":null}')),
      ),
    ).not.toHaveProperty('minAnchorSlotsHeld');
    expect(JSON.parse(policyFileToJson(policyFileFromPolicy({ issuers: ['a'], minAnchorSlotsHeld: 2 }))).minAnchorSlotsHeld).toBe(
      2,
    );
  });
});

// ---------------------------------------------------------------------------
// The digest, unmoved.
// ---------------------------------------------------------------------------

describe('a demand nobody stated moves no digest', () => {
  /**
   * Pinned literally, from before this field existed: the two published policy digests `policy-schema.test.ts`
   * carries. A canonical form that wrote the new key out for a policy that never named it would move both,
   * and every citation of them with it, which is the trade this file declines beside the reason at
   * `canonicalOf`.
   */
  const before: Array<[label: string, document: Record<string, unknown>]> = [
    [
      'the policy that names one issuer',
      { v: 1, issuers: ['ashaveri-mock'] },
    ],
    [
      'the policy that pins everything',
      {
        v: 1,
        issuers: ['ashaveri-prod'],
        instances: ['cvm-1'],
        keys: { ['a'.repeat(64)]: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
        measurements: { snp: ['7f'.repeat(48)] },
        maxReceiptAgeSeconds: 60,
        maxEvidenceAgeSeconds: null,
        trustAnchors: {
          amdArks: [{ path: 'roots/ark.pem', sha256: 'ab'.repeat(32) }],
          intelSgxRoots: null,
          nvidiaRoots: [{ path: 'roots/device-ca.pem', sha256: 'cd'.repeat(32) }],
        },
      },
    ],
  ];
  const DIGESTS: Record<string, string> = {
    'the policy that names one issuer': 'sha256:3329595b14993b16992a6577f332a05b34821e33454a53a24575a1c9902c91d6',
    'the policy that pins everything': 'sha256:008742152d91f71b57ca1c63ddf29220d9b7b396cc77954e28575114a43cd373',
  };

  for (const [label, document] of before) {
    it(`keeps ${label}'s digest, stated or not`, () => {
      expect(DIGESTS[label]).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(policyFileDigest(parsePolicyFile(JSON.stringify(document)))).toBe(DIGESTS[label]);
      // The demand spelled as null, and the demand spelled as the file the loader wrote back out: one
      // identity each way, because an unstated demand never enters the canonical form.
      expect(policyFileDigest(parsePolicyFile(JSON.stringify({ ...document, minAnchorSlotsHeld: null })))).toBe(
        DIGESTS[label],
      );
      const file = parsePolicyFile(JSON.stringify(document));
      expect(policyFileDigest(parsePolicyFile(policyFileToJson(file)))).toBe(DIGESTS[label]);
    });
  }

  it('moves when the demand moves, and separates one slot from two', () => {
    const none = policyFileDigest(parsePolicyFile('{"v":1,"issuers":["a"]}'));
    const one = policyFileDigest(parsePolicyFile('{"v":1,"issuers":["a"],"minAnchorSlotsHeld":1}'));
    const two = policyFileDigest(parsePolicyFile('{"v":1,"issuers":["a"],"minAnchorSlotsHeld":2}'));
    expect(new Set([none, one, two]).size).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// The schema, agreeing with the loader.
// ---------------------------------------------------------------------------

describe('the policy schema and the loader decide the same anchor demand', () => {
  const schemaPath = fileURLToPath(new URL('../schemas/policy-v1.schema.json', import.meta.url));
  const readSchema = (): object => JSON.parse(readFileSync(schemaPath, 'utf8')) as object;

  it('states the bounds the loader runs', () => {
    const schema = readSchema() as {
      properties: { minAnchorSlotsHeld: { type: string[]; minimum: number; maximum: number } };
    };
    expect(schema.properties.minAnchorSlotsHeld.maximum).toBe(MAX_ANCHOR_SLOTS_DEMANDABLE);
    expect(schema.properties.minAnchorSlotsHeld.minimum).toBe(1);
    expect(schema.properties.minAnchorSlotsHeld.type).toEqual(['integer', 'null']);
  });

  it('accepts what the loader accepts and refuses what it refuses', () => {
    const validate = new Ajv2020({ strict: true }).compile(readSchema());
    for (const value of [1, 2, null]) {
      const document = { v: 1, issuers: ['a'], minAnchorSlotsHeld: value };
      expect(loaderAccepts(document), JSON.stringify(document)).toBe(true);
      expect(validate(document), JSON.stringify(document)).toBe(true);
    }
    const noKey = { v: 1, issuers: ['a'] };
    expect(loaderAccepts(noKey)).toBe(true);
    expect(validate(noKey)).toBe(true);
    for (const value of [0, -1, 1.5, MAX_ANCHOR_SLOTS_DEMANDABLE + 1, '2', true, {}, [1], Number.MAX_SAFE_INTEGER + 2]) {
      const document = { v: 1, issuers: ['a'], minAnchorSlotsHeld: value };
      expect(loaderAccepts(document), JSON.stringify(document)).toBe(false);
      expect(validate(document), JSON.stringify(document)).toBe(false);
    }
  });
});

describe("the demand's ceiling is the anchor's own slot count", () => {
  /**
   * How many slots an anchor states belongs to the format, as the member list it declares for the closed map
   * at `cva`. That list is not re-exported from the package's entry point on purpose, so the two spellings are
   * held to each other the way `packages/receipt/test/disclosure.test.ts` holds the presence labels: read the
   * declaration out of the source it lives in and compare the lists, so a third slot moves this ceiling by a
   * failing test and not by a number nobody remembered to change.
   */
  it('matches the member list the codec declares', () => {
    const source = readFileSync(fileURLToPath(new URL('../../receipt/src/receipt.ts', import.meta.url)), 'utf8');
    const line = /export const COLLATERAL_ANCHOR_MEMBERS = \[([^\]]+)\] as const;/u.exec(source)?.[1];
    if (line === undefined) throw new Error('receipt.ts no longer declares COLLATERAL_ANCHOR_MEMBERS in a readable shape');
    const spelled = [...line.matchAll(/'([^']+)'/gu)].map((found) => found[1]!);
    expect(spelled).toEqual(['col', 'val']);
    expect(spelled.length).toBe(MAX_ANCHOR_SLOTS_DEMANDABLE);
  });
});

// ---------------------------------------------------------------------------
// The refusal, per shape and per posture.
// ---------------------------------------------------------------------------

describe('an anchor weighed against the demand', () => {
  /** Every shape, under every posture the field can be in, with each verdict pinned as a string. */
  const table: Array<[shape: string, heldSlots: number, expect: Record<string, string>]> = [
    ['both held', 2, { none: 'verify-ok', one: 'verify-ok', two: 'verify-ok' }],
    ['collateral held, validity absent at source', 1, { none: 'verify-ok', one: 'verify-ok', two: 'ANCHOR_SLOT_NOT_HELD' }],
    ['collateral absent at source, validity held', 1, { none: 'verify-ok', one: 'verify-ok', two: 'ANCHOR_SLOT_NOT_HELD' }],
    ['collateral held, validity never taken in', 1, { none: 'verify-ok', one: 'verify-ok', two: 'ANCHOR_SLOT_NOT_HELD' }],
    ['both never taken in', 0, { none: 'verify-ok', one: 'ANCHOR_SLOT_NOT_HELD', two: 'ANCHOR_SLOT_NOT_HELD' }],
    ['both absent at source', 0, { none: 'verify-ok', one: 'ANCHOR_SLOT_NOT_HELD', two: 'ANCHOR_SLOT_NOT_HELD' }],
  ];

  it('answers the table it states, for every shape and posture', () => {
    expect(table.map(([shape]) => shape).sort()).toEqual(Object.keys(ANCHORS).sort());
    for (const [shape, heldSlots, owed] of table) {
      const anchor = ANCHORS[shape]!;
      const receipt = receiptOver(3, anchor);
      // The count the posture is decided on is read off the shape beside it, so the two cannot drift.
      const slots = [anchor.collateral, anchor.validity];
      expect(slots.filter((slot) => slot.presence === 'held').length, shape).toBe(heldSlots);
      expect(verdict(receipt, undefined), `${shape} with no policy at all`).toBe(owed['none']);
      expect(verdict(receipt, NO_DEMAND), `${shape} with a policy naming no demand`).toBe(owed['none']);
      expect(verdict(receipt, demandOf(1)), `${shape} under a demand of 1`).toBe(owed['one']);
      expect(verdict(receipt, demandOf(2)), `${shape} under a demand of 2`).toBe(owed['two']);
    }
  });

  it('reaches the demand through a document as well as through an object', async () => {
    const receipt = receiptOver(3, ANCHORS['collateral held, validity never taken in']!);
    const two = await loadPolicyFromText(docWith({ minAnchorSlotsHeld: 2 }), '.');
    expect(verdict(receipt, two.policy)).toBe('ANCHOR_SLOT_NOT_HELD');
    const one = await loadPolicyFromText(docWith({ minAnchorSlotsHeld: 1 }), '.');
    expect(verdict(receipt, one.policy)).toBe('verify-ok');
  });

  it('says which state reached it, whose slot it was, and what that slot said', () => {
    const message = messageOf(receiptOver(3, ANCHORS['collateral held, validity absent at source']!), demandOf(2));
    expect(message).toContain('the validity slot states its material was absent at the source');
    expect(message).toContain('absent-at-source');
    expect(message).toContain(CHAIN_GAP);
    expect(message).toContain('an anchor with 1 of 2 slots held');
    expect(message).toContain('this policy demands 2');
    // The held half is named as held and not swept into the gap, which is the one way this sentence could
    // state a count and a list that disagree with each other.
    expect(message).not.toContain('the collateral slot states');

    expect(messageOf(receiptOver(3, ANCHORS['collateral absent at source, validity held']!), demandOf(2))).toContain(
      'the collateral slot states',
    );

    const both = messageOf(receiptOver(3, ANCHORS['both never taken in']!), demandOf(1));
    expect(both).toContain('the collateral slot states that this deployment never took its material in');
    expect(both).toContain('the validity slot states that this deployment never took its material in');
    expect(both).toContain('an anchor with 0 of 2 slots held');
    expect(both).toContain(NOTHING_TAKEN);
    expect(both).toContain(COLLECTOR_GAP);
  });

  it('keeps its refusal one line of visible text, as every refusal is', () => {
    expect(messageOf(receiptOver(3, ANCHORS['both absent at source']!), demandOf(2)).split('\n')).toHaveLength(1);
  });
});

describe('what the demand does not reach', () => {
  it('leaves a document that states no anchor exactly where it was', () => {
    // A `v: 1` and a `v: 2` payload name no anchor, so they make no statement about presence either way.
    // That is the boundary of this rule and not a hole in it: refusing them would be a rule about version
    // numbers, and the row in docs/error-codes.md says so in the same words a caller reads.
    for (const version of [1, 2] as const) {
      const receipt = receiptOver(version);
      expect(verdict(receipt, undefined), `v${version} with no policy`).toBe('verify-ok');
      expect(verdict(receipt, demandOf(MAX_ANCHOR_SLOTS_DEMANDABLE)), `v${version} under the fullest demand`).toBe(
        'verify-ok',
      );
    }
  });

  it('weighs nothing about whether a held digest still resolves', () => {
    // The digests below are of bytes nobody holds and nothing can fetch. A `held` slot answers this demand
    // however thin the material behind the digest turns out to be, which is the half the next unit takes up
    // and the reason this one is the presence half.
    const thin: CollateralValidityAnchor = {
      collateral: { presence: 'held', sha256: new Uint8Array(32).fill(1) },
      validity: { presence: 'held', sha256: new Uint8Array(32).fill(2) },
    };
    expect(verdict(receiptOver(3, thin), demandOf(2))).toBe('verify-ok');
  });
});

// ---------------------------------------------------------------------------
// The property a reviewer checks first.
// ---------------------------------------------------------------------------

describe('a policy naming nothing changes no existing verdict', () => {
  /**
   * Verdicts pinned as strings, from the shipped behaviour and not from a second call to the same function:
   * the claim is that no policy at all and a policy that names pins but no anchor demand answer the same for
   * every shape, including the shapes that refuse for reasons of their own. Comparing the two calls against
   * each other would prove nothing, because a guard that fired on an absent demand refuses both.
   */
  const cases: Array<[label: string, receipt: Uint8Array, answer: string, responseBytes?: Uint8Array]> = [
    ['a v1 receipt', receiptOver(1), 'verify-ok'],
    ['a v2 receipt', receiptOver(2), 'verify-ok'],
    ['a v3 receipt with both slots held', receiptOver(3, ANCHORS['both held']!), 'verify-ok'],
    ['a v3 receipt with both gaps stated', receiptOver(3, ANCHORS['both never taken in']!), 'verify-ok'],
    ['a v3 receipt with one slot held', receiptOver(3, ANCHORS['collateral held, validity absent at source']!), 'verify-ok'],
    ['a receipt signed by another key', receiptOver(3, ANCHORS['both held']!, OTHER_KEY), 'receipt:KID_MISMATCH'],
    ['a marked receipt handed bytes it does not attest', receiptOver(2), 'RESPONSE_HASH_MISMATCH', utf8('the body some other completion served')],
  ];

  for (const [label, receipt, answer, responseBytes] of cases) {
    it(`${label}: ${answer} either way round`, () => {
      expect(verdict(receipt, undefined, responseBytes)).toBe(answer);
      expect(verdict(receipt, NO_DEMAND, responseBytes)).toBe(answer);
      expect(verdict(receipt, { issuers: ['dpl-9f2a41c3'], maxReceiptAgeSeconds: 3600 }, responseBytes)).toBe(answer);
    });
  }

  it('refuses on the pins it always refused on, ahead of the demand', () => {
    const receipt = receiptOver(3, ANCHORS['both never taken in']!);
    expect(verdict(receipt, { issuers: ['someone-else'] })).toBe('ISSUER_NOT_ALLOWED');
    // A receipt this policy would not trust an issuer from is not also asked about its anchor: the earlier
    // question is the answer a caller gets, which is the order the pins have always kept.
    expect(verdict(receipt, { issuers: ['someone-else'], minAnchorSlotsHeld: 2 })).toBe('ISSUER_NOT_ALLOWED');
    expect(verdict(receipt, demandOf(2))).toBe('ANCHOR_SLOT_NOT_HELD');
  });

  it('reaches the same verdict through a designated key as through a handed one', () => {
    const receipt = receiptOver(3, ANCHORS['both held']!);
    const policy: AshaveriPolicy = { issuers: ['dpl-9f2a41c3'], keys: { [KID]: toBase64Url(KEY.publicKey) } };
    expect(policyKeyByKid(policy, KEY.kid)).toEqual(KEY.publicKey);
    expect(verdict(receipt, policy)).toBe('verify-ok');
    expect(verdict(receipt, { ...policy, minAnchorSlotsHeld: 2 })).toBe('verify-ok');
  });
});
