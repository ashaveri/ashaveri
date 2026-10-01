import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  hashRequest,
  issueReceipt,
  signingKeyFromSeed,
  type CollateralValidityAnchor,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import {
  ATTESTED_TEXT_MEMBERS,
  MAX_ANCHOR_SLOTS_DEMANDABLE,
  SdkError,
  loadPolicyFromText,
  parsePolicyFile,
  policyFileDigest,
  policyFileFromPolicy,
  policyFileToJson,
  toHex,
  verifyCompletionReceipt,
  type AnchorSlotReading,
  type AshaveriPolicy,
} from '../src/index.js';

/**
 * The demand a policy can make about the material behind an anchor's `held` slots.
 *
 * `minAnchorSlotsHeld` asks the artifact what it stated at issuance and is answered by reading it. This one asks what
 * a reader can still weigh: whether the digest a slot names resolves inside the scope that reader holds, and whether
 * the material behind it stands as its own signed statement at the instant the record claims. The readings arrive from
 * wherever the material does, which for a pack is the format package's own `resolveCarried` and for a vendor document
 * the collateral package's appraisal, so every verdict below is reached through `verifyCompletionReceipt` with those
 * readings handed to it, and not through the comparison function beside it, which a caller could call wrongly and this
 * file would never notice.
 *
 * Three properties hold this file together. A policy naming no demand moves no digest and no verdict, pinned as values
 * rather than as a sentence. The two refusals stay the two gaps they name, an unreached digest and reached material
 * that does not stand, because an operator told "the anchor failed" learns nothing from either. And the window is
 * weighed against the instant the record states rather than against the state an appraisal settled on: a container
 * seals no observation instant, so material read out of one is never a current answer and never arrives with a closed
 * window beside it, and a demand that asked the appraisal which of those it met would report a retired document as an
 * unobserved archive.
 */

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(11));
const IAT = 1_772_000_000;
const NONCE = new Uint8Array(16).fill(3);
const REQUEST_HASH = new Uint8Array(32).fill(4);
const EMPTY = new Uint8Array(0);
const RESPONSE_HASH = hashRequest(EMPTY);
const MEASUREMENT = new Uint8Array(48).fill(6);
const ISSUER = 'dpl-9f2a41c3';

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const held = (label: string) => ({ presence: 'held' as const, sha256: hashRequest(utf8(label)) });
const absent = (reason: string) => ({ presence: 'absent-at-source' as const, reason });
const notTakenIn = (reason: string) => ({ presence: 'not-taken-in' as const, reason });

/** The digests the two slots of the anchor below state, spelled the way a reading spells them: lowercase hex. */
const COL_DIGEST = toHex(hashRequest(utf8('collateral bytes')));
const VAL_DIGEST = toHex(hashRequest(utf8('validity bytes')));
const OTHER_BYTES_DIGEST = toHex(hashRequest(utf8('a document from some other machine')));

const COLLATERAL_GAP = 'the source published no chain for this chip';
const COLLECTOR_GAP = 'this issuer records no validity context at issuance';

const ANCHORS: Record<string, CollateralValidityAnchor> = {
  'both held': { collateral: held('collateral bytes'), validity: held('validity bytes') },
  'collateral held, validity never taken in': {
    collateral: held('collateral bytes'),
    validity: notTakenIn(COLLECTOR_GAP),
  },
  'both absent at source': {
    collateral: absent(COLLATERAL_GAP),
    validity: absent('the source published no window for this level'),
  },
};

/**
 * The window this run's material states for itself, beside the instant the record claims.
 *
 * `COVERING` reaches `IAT` the way the format's own arithmetic says a window does: from its first second up to but not
 * including its last. `RETIRED` closed before the record was stamped, which is a material retired on schedule and not
 * a forgery, and `EDGE` ends at the very second the record states, so the instant falls outside it by that same rule.
 */
const COVERING = { from: IAT - 3_600, until: IAT + 3_600 };
const RETIRED = { from: IAT - 86_400, until: IAT - 3_600 };
const EDGE = { from: IAT - 1, until: IAT };

function payloadOver(cva: CollateralValidityAnchor): ReceiptPayload {
  return {
    v: 1,
    iss: ISSUER,
    ins: 'cvm-i-047f2a',
    iat: IAT,
    nce: NONCE,
    req: REQUEST_HASH,
    res: RESPONSE_HASH,
    mdl: 'mock-model-1',
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'snp', m: MEASUREMENT },
    att: { d: new Uint8Array(32).fill(9), ts: IAT - 60, url: 'https://inference.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
    mk: { sch: 'none', d: RESPONSE_HASH },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva,
    itm: [{ t: IAT - 1, d: hashRequest(utf8('the one item of a buffered body')) }],
  };
}

const receiptOver = (cva: CollateralValidityAnchor): Uint8Array => issueReceipt(payloadOver(cva), KEY);

/**
 * One receipt handed to the shipped client path, with the readings a caller holding the material would hand beside it.
 *
 * The clock is the instant the document states, so no verdict below is one of the two windows'; the marking is the
 * empty region `sch: none` names, so the response checks hold; and the only thing that moves between rows is what this
 * run was told about the bytes behind the digests.
 */
function verdict(
  receiptBytes: Uint8Array,
  policy: AshaveriPolicy | undefined,
  readings: readonly AnchorSlotReading[] = [],
): string {
  try {
    verifyCompletionReceipt({
      receiptBytes,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: EMPTY,
      verifyKey: KEY.publicKey,
      anchorReadings: readings,
      ...(policy === undefined ? {} : { policy }),
      nowMillis: IAT * 1000,
    });
    return 'verify-ok';
  } catch (err) {
    if (err instanceof SdkError) return err.code;
    const code = (err as { code?: string })?.code;
    return typeof code === 'string' ? `receipt:${code}` : `unexpected:${String(err)}`;
  }
}

function messageOf(receiptBytes: Uint8Array, policy: AshaveriPolicy, readings: readonly AnchorSlotReading[]): string {
  try {
    verifyCompletionReceipt({
      receiptBytes,
      nonce: NONCE,
      requestHash: REQUEST_HASH,
      responseHash: RESPONSE_HASH,
      responseBytes: EMPTY,
      verifyKey: KEY.publicKey,
      anchorReadings: readings,
      policy,
      nowMillis: IAT * 1000,
    });
    return '';
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

/**
 * One reading, spelled the way the caller that reached the material spells it.
 *
 * `reached` and `resolvedDigest` arrive together out of the format's lookup, which re-hashes the bytes it hands back,
 * so a reading that says it reached bytes states what they hash to. The two are separated here rather than merged
 * because the gap between them is the finding: bytes that hash to something else are a container disagreeing with the
 * digest the anchor named, which no window reading answers.
 */
function reading(over: Partial<Omit<AnchorSlotReading, 'slot' | 'digest'>> & Pick<AnchorSlotReading, 'slot'> & {
  digest?: string;
}): AnchorSlotReading {
  const digest = over.digest ?? (over.slot === 'col' ? COL_DIGEST : VAL_DIGEST);
  return {
    slot: over.slot,
    digest,
    reached: over.reached ?? true,
    resolvedDigest: over.resolvedDigest ?? (over.reached === false ? undefined : digest),
    signature: over.signature ?? 'established',
    window: over.window === undefined ? COVERING : over.window,
  };
}

/** The readings that answer for both slots of `ANCHORS['both held']`. */
const bothStood = (): AnchorSlotReading[] => [reading({ slot: 'col' }), reading({ slot: 'val' })];

/**
 * Both slots handed a reading, the collateral one spelled over.
 *
 * A demand of one is met by the validity slot standing on its own, so every row below that wants to see *which*
 * reading of the collateral failed has to demand both. Handing one slot only would answer the earlier gap, that the
 * other was never reached, and the sentence this file is checking would never be reached either.
 */
const bothOver = (over: Partial<Omit<AnchorSlotReading, 'slot' | 'digest'>>): AnchorSlotReading[] => [
  reading({ slot: 'col', ...over }),
  reading({ slot: 'val' }),
];

/** A policy that pins the issuer, which the client checks before it weighs any anchor, and names no demand of its own. */
const NO_DEMAND: AshaveriPolicy = { issuers: [ISSUER] };
const demandOf = (slots: number): AshaveriPolicy => ({ issuers: [ISSUER], minAnchorSlotsWeighed: slots });

/**
 * The ceiling read out of the format's own source rather than restated.
 *
 * `COLLATERAL_ANCHOR_MEMBERS` is the list `packages/receipt/src/receipt.ts` declares and the CDDL mirrors, so its
 * length is how many slots an anchor states. Reading the digits out of `MAX_ANCHOR_SLOTS_DEMANDABLE` would let this
 * file agree with itself, which is the shape of a witness that witnesses nothing.
 */
function formatSlotCount(): number {
  const source = readFileSync(new URL('../../receipt/src/receipt.ts', import.meta.url), 'utf8');
  const list = /export const COLLATERAL_ANCHOR_MEMBERS = \[([^\]]*)\] as const/u.exec(source);
  if (list === null) throw new Error('the anchor member list is not in the format source this test reads');
  return list[1]!.split(',').filter((entry) => entry.trim().length > 0).length;
}

describe('the ceiling a weighed demand may state is the format\'s own slot count', () => {
  it('is the length of the member list the codec declares', () => {
    expect(formatSlotCount()).toBe(MAX_ANCHOR_SLOTS_DEMANDABLE);
  });
});

describe('the shapes a document demands of a deployment\'s text', () => {
  /** The eight positions the loader knows, read out of the constant the check itself iterates. */
  const POSITIONS = ['iss', 'ins', 'mdl', 'att.url', 'mk.sch', 'sd.name', 'cva.col.r', 'cva.val.r'];

  it('reads the shapes into the policy they name', async () => {
    const loaded = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: { iss: '^dpl-[a-f0-9]{8}$', 'sd.name': '^[a-z ]+$' } }),
      '/tmp',
    );
    expect(loaded.policy.attestedTextShapes, 'both positions the operator named came back').toEqual({
      'sd.name': '^[a-z ]+$',
      iss: '^dpl-[a-f0-9]{8}$',
    });
    expect(loaded.file.attestedTextShapes, 'and the document spells them in the order the format sorts').toEqual({
      iss: '^dpl-[a-f0-9]{8}$',
      'sd.name': '^[a-z ]+$',
    });
  });

  it('reads an absent field and an explicit null as one policy that demands nothing', async () => {
    const spelled = await loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: null }), '/tmp');
    const omitted = await loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER] }), '/tmp');
    expect(spelled.policy.attestedTextShapes).toBeUndefined();
    expect(spelled.digest, 'null and absence are one policy and one digest').toBe(omitted.digest);
    expect(policyFileToJson(omitted.file), 'and neither writes a key').not.toContain('attestedTextShapes');
  });

  it('knows the positions the receipt format declares and no others', async () => {
    const loaded = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: Object.fromEntries(POSITIONS.map((one) => [one, '^[A-Za-z0-9._:-]{1,128}$'])) }),
      '/tmp',
    );
    expect(Object.keys(loaded.policy.attestedTextShapes ?? {}).sort(), 'every position the loader takes is one the check runs')
      .toEqual([...POSITIONS].sort());
    for (const stray of ['v', 'mdl ', 'iat', 'cva', 'wts', 'nothing']) {
      await expect(
        loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: { [stray]: '^a$' } }), '/tmp'),
      ).rejects.toThrow(/attestedTextShapes/u);
    }
  });

  it('refuses a source that compiles to nothing, and one the empty text matches', async () => {
    for (const source of ['^(', 'a*', '^$', '', '^[a-z$']) {
      await expect(
        loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: { iss: source } }), '/tmp'),
      ).rejects.toThrow(/attestedTextShapes/u);
    }
  });

  it('refuses a map naming no position at all, the way an empty pin list is refused', async () => {
    let code = 'nothing thrown';
    try {
      parsePolicyFile(JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: {} }));
    } catch (err) {
      code = err instanceof SdkError ? err.code : `not an SdkError: ${String(err)}`;
    }
    expect(code, 'a rule written over no member demands nothing, so the road out is to leave the field out')
      .toBe('POLICY_EMPTY_PIN');
  });

  it('carries the shapes through the object, the file and the read-back', async () => {
    const written = policyFileFromPolicy({ issuers: [ISSUER], attestedTextShapes: { mdl: '^[a-z-]{1,32}$' } });
    expect(written.attestedTextShapes).toEqual({ mdl: '^[a-z-]{1,32}$' });
    const text = policyFileToJson(written);
    const reloaded = await loadPolicyFromText(text, '/tmp');
    expect(reloaded.policy.attestedTextShapes, 'the shape the object named comes back out of the file').toEqual({
      mdl: '^[a-z-]{1,32}$',
    });
    expect(reloaded.digest, 'and the digest is over the document that states it').toBe(policyFileDigest(written));
  });

  it('keeps one digest for the same shapes written in two orders', async () => {
    const one = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: { iss: '^a+$', ins: '^b+$' } }),
      '/tmp',
    );
    const two = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: { ins: '^b+$', iss: '^a+$' } }),
      '/tmp',
    );
    expect(two.digest, 'two documents meaning one policy give one digest').toBe(one.digest);
    const widened = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], attestedTextShapes: { iss: '^[ab]+$' } }),
      '/tmp',
    );
    expect(widened.digest, 'and a different shape is a different policy').not.toBe(one.digest);
  });

  it('holds the shape class to the text the payload actually carries', () => {
    /**
     * Every text member a receipt payload declares, by the path a policy keys a shape by.
     *
     * Read out of `packages/receipt/receipt.cddl`, the file the format's own shape is written in, rather than out of a
     * payload object: the object an anchor builds names its halves `collateral` and `validity` while the signed bytes
     * name them `col` and `val`, so walking one document and comparing it with this file's list would let the list agree
     * with itself. A member declared `tstr`, or as one label beside a `tstr`, is text somebody wrote; a member declared
     * only as quoted literals is a closed set the format already validates, and `v: 1` is neither. A ninth text member
     * in the format reddens this row instead of going unweighed.
     */
    const source = readFileSync(new URL('../../receipt/receipt.cddl', import.meta.url), 'utf8');
    const maps = new Map<string, string[]>();
    const aliases = new Map<string, string[]>();
    let open: string[] | null = null;
    for (const rawLine of source.split('\n')) {
      const line = (rawLine.split(';')[0] ?? '').trim();
      if (line.length === 0) continue;
      const defined = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/u.exec(line);
      if (defined !== null) {
        const [, name, rest] = defined;
        if (rest === '{') {
          open = maps.get(name) ?? [];
          maps.set(name, open);
          continue;
        }
        open = null;
        aliases.set(name, rest.split('/').map((one) => one.trim()).filter((one) => one.length > 0));
        continue;
      }
      if (line === '}') {
        open = null;
        continue;
      }
      if (line === '} / {' || open === null) continue;
      const member = /^([A-Za-z0-9_-]+)\s*:\s*(.+)$/u.exec(line);
      if (member !== null) open.push(`${member[1]} ${member[2]}`);
    }
    const membersOf = (name: string): string[] | undefined => {
      const own = maps.get(name);
      if (own !== undefined) return own;
      const spelled = aliases.get(name);
      if (spelled === undefined) return undefined;
      const merged: string[] = [];
      for (const each of spelled) merged.push(...(membersOf(each) ?? []));
      return merged.length > 0 ? merged : undefined;
    };
    const declared = membersOf('Ashaveri-Receipt-Payload');
    if (declared === undefined || declared.length === 0) {
      throw new Error('the payload map is not in the CDDL this test reads, so it witnesses nothing');
    }
    const paths = new Set<string>();
    const collect = (entries: readonly string[], prefix: string): void => {
      for (const entry of entries) {
        const split = entry.indexOf(' ');
        const key = entry.slice(0, split);
        const expr = entry.slice(split + 1);
        const path = prefix === '' ? key : `${prefix}.${key}`;
        if (/\btstr\b/u.test(expr)) {
          paths.add(path);
          continue;
        }
        for (const token of expr.split(/[^A-Za-z0-9_-]+/u).filter((one) => one.length > 0)) {
          const nested = membersOf(token);
          if (nested !== undefined) collect(nested, path);
        }
      }
    };
    collect(declared, '');
    expect([...paths].sort(), 'the positions a shape can be demanded of are the text the payload declares')
      .toEqual([...ATTESTED_TEXT_MEMBERS].sort());
    expect(paths.has('v'), 'a version number is what this reader was built to parse, not text').toBe(false);
    expect(paths.has('meas.tee'), 'and a closed set of labels is not a sentence an operator shapes').toBe(false);
    expect(paths.has('cva.col.r'), 'the anchor\'s reasons are named as the signed bytes name them').toBe(true);
  });
});

describe('the shapes weighed against a receipt, in the shipped client path', () => {
  const bytes = receiptOver(ANCHORS['both held']!);

  /** One policy pinning its issuer and naming shapes for the members a row names. */
  const shaped = (shapes: Record<string, string>): AshaveriPolicy => ({
    issuers: [ISSUER],
    attestedTextShapes: shapes as AshaveriPolicy['attestedTextShapes'],
  });

  it('passes the text this receipt states under the shape the policy names for it', () => {
    expect(verdict(bytes, shaped({ iss: '^dpl-[a-f0-9]{8}$' }))).toBe('verify-ok');
    expect(verdict(bytes, shaped({ mdl: '^[a-z0-9-]{4,32}$', 'sd.name': '^[a-z ]{1,32}$' }))).toBe('verify-ok');
  });

  it('refuses a member outside the shape, and names the position and the shape without the value', () => {
    const code = verdict(bytes, shaped({ iss: '^prod-.*$' }));
    expect(code).toBe('ATTESTED_TEXT_OUTSIDE_SHAPE');
    const message = messageOf(bytes, shaped({ iss: '^prod-.*$' }), []);
    expect(message).toContain('iss');
    expect(message, 'the refusal quotes the demand back').toContain('^prod-.*$');
    expect(message, 'and the length of what was found, but never the text itself').toContain(`${ISSUER.length} characters`);
    expect(message).not.toContain(ISSUER);
  });

  it('skips the absence reason of a slot that states it holds its material, and weighs one that states a reason', () => {
    expect(
      verdict(bytes, shaped({ 'cva.col.r': '^never$' })),
      'a held slot states no sentence, so there is nothing here for the rule to run over',
    ).toBe('verify-ok');
    const gap = notTakenIn('this issuer takes no collateral into the record it signs with');
    const reasoned = receiptOver({ collateral: gap, validity: gap });
    expect(verdict(reasoned, NO_DEMAND), 'the same document asks nothing of a policy naming no shape').toBe('verify-ok');
    expect(
      verdict(reasoned, shaped({ 'cva.col.r': '^the source published' })),
      'and a rule over the collector\'s own sentence is reached where the sentence exists',
    ).toBe('ATTESTED_TEXT_OUTSIDE_SHAPE');
    expect(
      verdict(reasoned, shaped({ 'cva.val.r': '^this issuer takes no collateral.*$' })),
      'and the other slot\'s sentence is weighed by the same rule',
    ).toBe('verify-ok');
    expect(
      verdict(reasoned, shaped({ 'cva.val.r': '^never$' })),
      'and refused by it the same way',
    ).toBe('ATTESTED_TEXT_OUTSIDE_SHAPE');
  });

  it('weighs every position the class holds, both directions', () => {
    const rows: ReadonlyArray<readonly [member: string, shape: string, verdict: string]> = [
      ['iss', '^dpl-[a-f0-9]{8}$', 'verify-ok'],
      ['iss', '^prod-[a-f0-9]{8}$', 'ATTESTED_TEXT_OUTSIDE_SHAPE'],
      ['ins', '^cvm-i-[a-f0-9]{6}$', 'verify-ok'],
      ['ins', '^nope', 'ATTESTED_TEXT_OUTSIDE_SHAPE'],
      ['mdl', '^mock-model-1$', 'verify-ok'],
      ['mdl', '^[0-9]+$', 'ATTESTED_TEXT_OUTSIDE_SHAPE'],
      ['att.url', '^https://inference\\.example/v1/attestation$', 'verify-ok'],
      ['att.url', '^http://', 'ATTESTED_TEXT_OUTSIDE_SHAPE'],
      ['mk.sch', '^none$', 'verify-ok'],
      ['mk.sch', '^provenance-v1$', 'ATTESTED_TEXT_OUTSIDE_SHAPE'],
      ['sd.name', '^host clock$', 'verify-ok'],
      ['sd.name', '^ptp-disciplined.*', 'ATTESTED_TEXT_OUTSIDE_SHAPE'],
    ];
    for (const [member, shape, expected] of rows) {
      expect(verdict(bytes, shaped({ [member]: shape })), `${member} against ${shape}`).toBe(expected);
    }
  });
});
describe('the count of slots a document demands be weighed', () => {
  it('reads the demand into the policy it names', async () => {
    const loaded = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], minAnchorSlotsWeighed: 2 }),
      '/tmp',
    );
    expect(loaded.policy.minAnchorSlotsWeighed, 'a stated demand reads as the number it states').toBe(2);
    expect(loaded.file.minAnchorSlotsWeighed).toBe(2);
  });

  it('reads an absent field and an explicit null as one policy that demands nothing', async () => {
    const spelled = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: [ISSUER], minAnchorSlotsWeighed: null }),
      '/tmp',
    );
    const omitted = await loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER] }), '/tmp');
    expect(spelled.policy.minAnchorSlotsWeighed, 'a null demand asks nothing of an anchor\'s material').toBeUndefined();
    expect(omitted.policy.minAnchorSlotsWeighed, 'so does an absent one').toBeUndefined();
    expect(spelled.digest, 'and both are the policy that never named the field, digest for digest').toBe(omitted.digest);
  });

  it('carries one demand through the object, the file and the read-back', () => {
    const written = policyFileFromPolicy(demandOf(1));
    expect(written.minAnchorSlotsWeighed, 'the object\'s demand reaches the document').toBe(1);
    expect(policyFileToJson(written)).toContain('"minAnchorSlotsWeighed": 1');
  });

  it('writes the key only where a demand was stated', () => {
    expect(policyFileToJson(policyFileFromPolicy(NO_DEMAND)), 'a policy demanding nothing names no key')
      .not.toContain('minAnchorSlotsWeighed');
  });
});

describe('the loader refuses a weighed demand no policy can carry', () => {
  const malformed: ReadonlyArray<readonly [label: string, demand: unknown]> = [
    ['0', 0],
    ['-1', -1],
    ['1.5', 1.5],
    ['3', 3],
    ['a string', '2'],
    ['true', true],
    ['an array', [2]],
  ];

  for (const [label, demand] of malformed) {
    it(`refuses ${label} on the way in and on the way out`, async () => {
      await expect(
        loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER], minAnchorSlotsWeighed: demand }), '/tmp'),
      ).rejects.toThrow(/minAnchorSlotsWeighed/u);
      expect(
        (() => {
          try {
            policyFileFromPolicy({ issuers: [ISSUER], minAnchorSlotsWeighed: demand as number });
            return null;
          } catch (err) {
            return err instanceof SdkError ? err.code : `not an SdkError: ${String(err)}`;
          }
        })(),
        `${label} is refused on the road out of the object too, not only on the road in`,
      ).toBe('POLICY_FILE_INVALID');
    });
  }

  it('refuses the spelling a JSON document can carry and no reader can state exactly', async () => {
    // Written as text rather than through `JSON.stringify`, which turns `1e400` into `null` and so into this format's
    // spelling of a demand nobody made. A file of digits the loader cannot hold exactly is two demands in one document:
    // what the operator wrote and what the verifier ran, which is why `Number.isSafeInteger` is the guard.
    await expect(loadPolicyFromText('{"v":1,"issuers":["a"],"minAnchorSlotsWeighed":1e400}', '/tmp'))
      .rejects.toThrow(/minAnchorSlotsWeighed/u);
    expect(
      (() => {
        try {
          policyFileFromPolicy({ issuers: [ISSUER], minAnchorSlotsWeighed: 1e400 });
          return 'nothing thrown';
        } catch (err) {
          return err instanceof SdkError ? err.code : `not an SdkError: ${String(err)}`;
        }
      })(),
      'and the object carrying the same figure is refused on the way out',
    ).toBe('POLICY_FILE_INVALID');
  });

  it('names the two roads open when the demand is a number no document can answer', async () => {
    const message = await loadPolicyFromText(JSON.stringify({ v: 1, issuers: [ISSUER], minAnchorSlotsWeighed: 0 }), '/tmp')
      .then(() => '', (err: unknown) => String(err));
    expect(message).toContain(`a whole number from 1 to ${MAX_ANCHOR_SLOTS_DEMANDABLE}`);
    expect(message, 'the loader says what demanding nothing looks like in this format').toContain('leave the field out');
  });

  it('refuses an infinite or not-a-number demand rather than let it arrive as its own absence', () => {
    for (const demand of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) {
      let code = 'nothing thrown';
      let message = '';
      try {
        policyFileFromPolicy({ issuers: [ISSUER], minAnchorSlotsWeighed: demand });
      } catch (err) {
        code = err instanceof SdkError ? err.code : `not an SdkError: ${String(err)}`;
        message = err instanceof Error ? err.message : String(err);
      }
      expect(code, `a demand of ${String(demand)} is refused rather than written out as null`).toBe('POLICY_FILE_INVALID');
      expect(message).toContain('minAnchorSlotsWeighed');
      expect(message, 'and the refusal says what null would have done with the demand').toContain('asks nothing');
    }
  });
});

describe('a weighed demand nobody stated moves no digest', () => {
  /**
   * Two documents and the digests they carried before this demand could be written at all.
   *
   * The numbers are copied from `test/policy-replay.test.ts`, which measures them against the reader of the commit this
   * branch was cut from, and they are the published vectors `test/policy-schema.test.ts` pins beside it. A canonical
   * form that wrote this key out for a policy that never named it would move both, and every citation of them with it,
   * which is the trade `canonicalOf` declines and this file holds to numbers rather than to a sentence about it.
   */
  const before: ReadonlyArray<readonly [label: string, document: Record<string, unknown>, digest: string]> = [
    ['the policy that names one issuer', { v: 1, issuers: ['ashaveri-mock'] }, 'sha256:3329595b14993b16992a6577f332a05b34821e33454a53a24575a1c9902c91d6'],
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
      'sha256:008742152d91f71b57ca1c63ddf29220d9b7b396cc77954e28575114a43cd373',
    ],
  ];

  for (const [label, document, digest] of before) {
    it(`keeps ${label}'s digest, stated or not`, async () => {
      expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      // `parsePolicyFile` and `policyFileDigest` rather than `loadPolicyFile`, because one of these documents pins
      // vendor roots by path and a digest is a fact about the document, not about the disk under it.
      const bare = parsePolicyFile(JSON.stringify(document));
      expect(policyFileDigest(bare), 'the number this document carried before the demand existed').toBe(digest);
      const spelledNull = parsePolicyFile(JSON.stringify({ ...document, minAnchorSlotsWeighed: null }));
      expect(policyFileDigest(spelledNull), 'a spelled null is the same policy and the same digest').toBe(digest);
      const stated = parsePolicyFile(JSON.stringify({ ...document, minAnchorSlotsWeighed: 1 }));
      expect(policyFileDigest(stated), 'and a demand an operator wrote is inside the identity it states')
        .not.toBe(digest);
      expect(policyFileToJson(bare), 'and the text worth putting in a repository names no such key')
        .not.toContain('minAnchorSlotsWeighed');
      expect(policyFileDigest(parsePolicyFile(policyFileToJson(bare))), 'and reads back as the same policy')
        .toBe(digest);
    });
  }

  it('moves when the demand moves, and separates one slot from two', async () => {
    const digests: string[] = [];
    for (const demand of [1, 2]) {
      digests.push((await loadPolicyFromText(JSON.stringify({ v: 1, issuers: ['a'], minAnchorSlotsWeighed: demand }), '/tmp')).digest);
    }
    const none = (await loadPolicyFromText(JSON.stringify({ v: 1, issuers: ['a'] }), '/tmp')).digest;
    expect(new Set([...digests, none]).size, 'three postures of one field are three policies').toBe(3);
  });

  it('tells a weighed demand apart from a held one of the same number', async () => {
    const held = (await loadPolicyFromText(JSON.stringify({ v: 1, issuers: ['a'], minAnchorSlotsHeld: 1 }), '/tmp')).digest;
    const weighed = (await loadPolicyFromText(JSON.stringify({ v: 1, issuers: ['a'], minAnchorSlotsWeighed: 1 }), '/tmp')).digest;
    expect(weighed, 'two counts of one number are two demands, and a digest that mixed them would cite the wrong one')
      .not.toBe(held);
  });

  it('names one digest for the document stating both counts', async () => {
    const both = await loadPolicyFromText(
      JSON.stringify({ v: 1, issuers: ['a'], minAnchorSlotsHeld: 1, minAnchorSlotsWeighed: 2 }),
      '/tmp',
    );
    const heldOnly = await loadPolicyFromText(JSON.stringify({ v: 1, issuers: ['a'], minAnchorSlotsHeld: 1 }), '/tmp');
    expect(both.policy.minAnchorSlotsHeld).toBe(1);
    expect(both.policy.minAnchorSlotsWeighed).toBe(2);
    expect(both.digest).not.toBe(heldOnly.digest);
    expect(policyFileToJson(both.file)).toContain('"minAnchorSlotsWeighed": 2');
  });
});

describe('the two refusals, and the states that reach neither', () => {
  /**
   * Every reading this demand answers, and the verdict the shipped client gives for it.
   *
   * The verdicts are stated here and decided by the code, so a row disagreeing with the shipped weighing is a red test
   * rather than a comment agreeing with itself. The order is the order of dependence: reach is asked before standing,
   * because a slot with nothing reached has no signature to weigh and no window to compare.
   */
  const table: ReadonlyArray<readonly [label: string, demand: number, readings: readonly AnchorSlotReading[], verdict: string]> = [
    ['both slots standing, demanded as two', 2, bothStood(), 'verify-ok'],
    ['both standing, demanded as one', 1, bothStood(), 'verify-ok'],
    ['one slot handed and standing, demanded as one', 1, [reading({ slot: 'col' })], 'verify-ok'],
    ['one slot handed and standing, demanded as two', 2, [reading({ slot: 'col' })], 'ANCHOR_MATERIAL_UNREACHED'],
    ['nothing handed at all', 1, [], 'ANCHOR_MATERIAL_UNREACHED'],
    ['a digest no container carries', 2, bothOver({ reached: false, resolvedDigest: undefined }), 'ANCHOR_MATERIAL_UNREACHED'],
    ['bytes hashing to something else', 2, bothOver({ resolvedDigest: OTHER_BYTES_DIGEST }), 'ANCHOR_MATERIAL_UNREACHED'],
    ['two readings naming the wrong slots', 1, [reading({ slot: 'val', digest: COL_DIGEST }), reading({ slot: 'col', digest: VAL_DIGEST })], 'ANCHOR_MATERIAL_UNREACHED'],
    ['reached and unsigned under these roots', 2, bothOver({ signature: 'not-established' }), 'ANCHOR_MATERIAL_NOT_STANDING'],
    ['reached, signed, and withdrawn by the vendor', 2, bothOver({ signature: 'withdrawn' }), 'ANCHOR_MATERIAL_NOT_STANDING'],
    ['reached, signed, stating no window', 2, bothOver({ window: null }), 'ANCHOR_MATERIAL_NOT_STANDING'],
    ['reached, signed, its window retired first', 2, bothOver({ window: RETIRED }), 'ANCHOR_MATERIAL_NOT_STANDING'],
    ['reached, signed, its window ending at the second', 2, bothOver({ window: EDGE }), 'ANCHOR_MATERIAL_NOT_STANDING'],
    ['reached, signed, its window starting at it', 2, bothOver({ window: { from: IAT, until: IAT + 1 } }), 'verify-ok'],
    ['a withdrawn collateral beside a standing validity, demanded as one', 1, bothOver({ signature: 'withdrawn' }), 'verify-ok'],
  ];

  it('answers the table it states, for every reading and posture', () => {
    const receipt = receiptOver(ANCHORS['both held']!);
    for (const [label, demand, readings, expected] of table) {
      expect(verdict(receipt, demandOf(demand), readings), `${label}: demanded ${String(demand)}`).toBe(expected);
    }
  });

  it('weighs nothing for a policy that named no demand, whatever it was handed', () => {
    const receipt = receiptOver(ANCHORS['both held']!);
    for (const readings of [[], bothStood(), [reading({ slot: 'col', signature: 'withdrawn' })]] as const) {
      expect(verdict(receipt, NO_DEMAND, readings), 'no demand named, and the document answers as it always did')
        .toBe('verify-ok');
    }
    expect(verdict(receipt, undefined, bothStood()), 'and a caller with no policy at all answers the same')
      .toBe('verify-ok');
  });

  it('reports an anchor stating fewer held slots than the demand names as the absence it is', () => {
    const receipt = receiptOver(ANCHORS['collateral held, validity never taken in']!);
    expect(
      verdict(receipt, demandOf(2), [reading({ slot: 'col' })]),
      'a slot stating never-taken-in names no material to reach, which is the presence question and already has a code',
    ).toBe('ANCHOR_SLOT_NOT_HELD');
    expect(verdict(receipt, demandOf(1), [reading({ slot: 'col' })]), 'the held half still answers a demand of one')
      .toBe('verify-ok');
    expect(
      verdict(receipt, demandOf(1), []),
      'and a reader that reached even that half is told it reached nothing',
    ).toBe('ANCHOR_MATERIAL_UNREACHED');
  });

  it('does not reach an anchor that states no material at all', () => {
    const receipt = receiptOver(ANCHORS['both absent at source']!);
    expect(verdict(receipt, demandOf(1), []), 'two absences state nothing to weigh, and the count refusal owns that')
      .toBe('ANCHOR_SLOT_NOT_HELD');
  });

  it('weighs the window the material states for itself, not the state an appraisal settled on', () => {
    const receipt = receiptOver(ANCHORS['both held']!);
    // Material read out of a sealed container arrives with no observation behind it: never a current answer, never a
    // window refusal beside it, and its own signed window covering the record's instant all the same. That is a weighed
    // slot here, and a `stale` answer with `COLLATERAL_NOT_OBSERVED` there, because the two are different questions.
    expect(verdict(receipt, demandOf(2), bothStood()), 'reached, signed, covering: stood').toBe('verify-ok');
    expect(
      verdict(receipt, demandOf(2), [reading({ slot: 'col', window: RETIRED }), reading({ slot: 'val' })]),
      'and the one that does not cover is the one reported',
    ).toBe('ANCHOR_MATERIAL_NOT_STANDING');
  });
});

describe('what each refusal says', () => {
  const receipt = () => receiptOver(ANCHORS['both held']!);

  it('names the slot, the digest and the reading that failed for an unreached anchor', () => {
    const message = messageOf(receipt(), demandOf(1), []);
    expect(message).toContain('collateral');
    expect(message, 'the refusal names the digest nobody reached').toContain(COL_DIGEST);
    expect(message).toContain('no reading');
    expect(message, 'and the count that answered is stated beside the count demanded').toContain('weighed');
  });

  it('names the bytes that disagree with the digest the anchor named', () => {
    const message = messageOf(receipt(), demandOf(2), bothOver({ resolvedDigest: OTHER_BYTES_DIGEST }));
    expect(message).toContain(OTHER_BYTES_DIGEST);
    expect(message, 'and says the reached bytes are a different object than the one named').toContain('different object');
  });

  it('separates a signature nobody establishes from a window that missed, in words', () => {
    const unsigned = messageOf(receipt(), demandOf(2), bothOver({ signature: 'not-established' }));
    const retired = messageOf(receipt(), demandOf(2), bothOver({ window: RETIRED }));
    const withdrawn = messageOf(receipt(), demandOf(2), bothOver({ signature: 'withdrawn' }));
    expect(unsigned).toContain('no signature');
    expect(retired, 'a window that missed is stated as a window that missed, with the instant asked').toContain('outside it');
    expect(retired).toContain(String(IAT));
    expect(withdrawn, 'a withdrawn level is stated as withdrawn and never folded into a window')
      .toContain('withdraws');
    expect(withdrawn).not.toContain('outside it');
    expect(retired).not.toContain('no signature');
  });

  it('keeps every refusal one line of visible text', () => {
    for (const readings of [[], bothOver({ window: RETIRED })] as const) {
      expect(messageOf(receipt(), demandOf(2), readings).split('\n'), 'one line, as every refusal is').toHaveLength(1);
    }
  });
});
