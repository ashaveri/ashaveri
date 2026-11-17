import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { Ajv2020 } from 'ajv/dist/2020.js';
import {
  DESTRUCTION_COPY_CLASSES,
  DESTRUCTION_OBJECT_KINDS,
  DESTRUCTION_REACH_NOT_REACHED,
  DESTRUCTION_REACH_REACHED,
  DESTRUCTION_RECEIPT_CONTENT_TYPE,
  DESTRUCTION_RECEIPT_ENTRY_MEMBERS,
  DESTRUCTION_RECEIPT_MANIFEST_MEMBERS,
  DESTRUCTION_UNREACHABLE_COPY_CLASSES,
  REDACTION_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodeDestructionReceipt,
  decodeRedaction,
  destructionObjectDigest,
  destructionReceiptSigStructure,
  encodeCanonical,
  encodeDestructionReceiptManifest,
  encodeDestructionReceiptProtectedHeader,
  sealDestructionReceipt,
  signDestructionReceipt,
  signRedaction,
  signingKeyFromSeed,
  toHex,
  verifyDestructionReceipt,
  type DestructionCopyClass,
  type DestructionReachEntry,
  type DestructionReceiptManifest,
  type DestructionReceiptVerifyOptions,
  type RedactionManifest,
  type SigningKey,
} from '../src/index.js';

/**
 * The destruction receipt: a signed statement of what one destruction reached, per copy class, beside the one
 * object and the one key it took.
 *
 * The properties the cases below are grouped around are the ones a reviewer holding only the published format
 * and these bytes is owed. That the document is closed, so no member arrives that the contract does not
 * define, including no member wide enough to carry key material. That every copy class the format enumerates
 * carries exactly one statement, so a silence cannot read as a reach. That the format will not state a reach
 * over a copy that left the deployment's hands. That the statement was sealed by a key other than the one it
 * names destroyed. And that the designation is a comparison rather than a caption: the digest is recomputed
 * over the bytes handed, and the kind is read out of those bytes' own signed header.
 *
 * Two sources of bytes, and the split is deliberate. Honest documents come from `signDestructionReceipt`, so
 * the writer is witnessed producing what the reader accepts, and every document meant to be refused is
 * assembled from the published pieces and re-sealed under the key its own header names, because a writer that
 * refuses a shape cannot be the one that publishes it.
 */

const KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(41));
const DESTROYED: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(42));
const AT = 1_766_016_000;
const STATES = 'one receipt and the key that encrypted its body, erased from the copies this deployment holds';
const CDDLPATH = fileURLToPath(new URL('../destruction-receipt.cddl', import.meta.url));
const SCHEMAPATH = fileURLToPath(new URL('../schemas/destruction-receipt-v1.schema.json', import.meta.url));
const ERRORSPATH = fileURLToPath(new URL('../src/errors.ts', import.meta.url));

/** A document of one of the kinds the registry names, so a designation can be checked against real bytes. */
const REDACTION_BYTES = signRedaction(
  {
    v: 1,
    at: AT,
    pack: new Uint8Array(32).fill(7),
    removed: ['receipt-1'],
    reduced: new Uint8Array(32).fill(8),
    states: 'a record lifted out of a closed pack',
  } satisfies RedactionManifest,
  KEY,
);

function reachTable(over: Partial<Record<DestructionCopyClass, number>> = {}): DestructionReachEntry[] {
  return DESTRUCTION_COPY_CLASSES.map((name) => ({
    class: name,
    outcome: (over[name] ?? DESTRUCTION_REACH_NOT_REACHED) as DestructionReachEntry['outcome'],
  }));
}

function baseManifest(over: Partial<DestructionReceiptManifest> = {}): DestructionReceiptManifest {
  return {
    v: 1,
    at: AT,
    object: destructionObjectDigest(REDACTION_BYTES),
    kind: 'ashaveri/redaction',
    key: DESTROYED.kid,
    reach: reachTable({ store: DESTRUCTION_REACH_REACHED, pack: DESTRUCTION_REACH_REACHED }),
    states: STATES,
    ...over,
  };
}

const HONEST = signDestructionReceipt(baseManifest(), KEY);

function thrownCode(run: () => unknown): string {
  try {
    run();
  } catch (reason) {
    return reason instanceof ReceiptError ? reason.code : `UNCODED ${String(reason)}`;
  }
  return 'accepted';
}

/** The payload map of a sealed receipt, which is what every refusal case edits one position of. */
function payloadOf(bytes: Uint8Array): Map<unknown, unknown> {
  const top = decodeCanonical(bytes) as unknown as { contents: unknown[] };
  return decodeCanonical((top.contents as [unknown, unknown, Uint8Array])[2]) as Map<unknown, unknown>;
}

/**
 * The one-edit mutant: this document's bytes with a single position of the manifest map replaced, re-sealed
 * under the same key, so a refusal is about the position its name states and nothing else.
 */
function mutant(edit: (root: Map<unknown, unknown>) => void, signer: SigningKey = KEY): Uint8Array {
  const root = payloadOf(HONEST);
  edit(root);
  return sealedUnder(encodeDestructionReceiptProtectedHeader(signer.kid), encodeCanonical(root), signer);
}

function sealedUnder(header: Uint8Array, payloadBytes: Uint8Array, signer: SigningKey = KEY): Uint8Array {
  const signature = ed25519.sign(destructionReceiptSigStructure(header, payloadBytes), signer.privateKey);
  return sealDestructionReceipt(header, payloadBytes, signature);
}

function headerWith(alter: (map: Map<unknown, unknown>) => void): Uint8Array {
  const map = decodeCanonical(encodeDestructionReceiptProtectedHeader(KEY.kid)) as Map<unknown, unknown>;
  alter(map);
  return encodeCanonical(map);
}

function readWith(over: Partial<DestructionReceiptVerifyOptions> = {}): DestructionReceiptVerifyOptions {
  return { publicKey: KEY.publicKey, ...over };
}

describe('the honest destruction receipt', () => {
  it('round-trips through its own writer and reader', () => {
    const manifest = baseManifest();
    const decoded = decodeDestructionReceipt(signDestructionReceipt(manifest, KEY));
    expect(decoded.manifest.at).toBe(AT);
    expect(toHex(decoded.manifest.object)).toBe(toHex(manifest.object));
    expect(decoded.manifest.kind).toBe('ashaveri/redaction');
    expect(toHex(decoded.manifest.key)).toBe(toHex(DESTROYED.kid));
    expect(decoded.manifest.states).toBe(STATES);
    expect(decoded.manifest.reach.map((one) => one.class)).toEqual([...DESTRUCTION_COPY_CLASSES]);
    expect(decoded.header.contentType).toBe(DESTRUCTION_RECEIPT_CONTENT_TYPE);
  });

  it('encodes to one byte string for one state, whatever order a caller built it in', () => {
    // The bytes are what a reviewer hashes and what the signature covers, so two writers of one state that
    // produced two byte strings would give one claim two digests.
    const stated = reachTable({ pack: DESTRUCTION_REACH_REACHED });
    const unordered: DestructionReceiptManifest = {
      states: STATES, key: DESTROYED.kid, reach: stated, kind: 'ashaveri/redaction',
      object: destructionObjectDigest(REDACTION_BYTES), at: AT, v: 1,
    };
    expect(toHex(encodeDestructionReceiptManifest(unordered))).toBe(
      toHex(encodeDestructionReceiptManifest({ ...baseManifest(), reach: stated })),
    );
    // The array order is a byte string and not a claim, so a reader accepts a list in any order and hands
    // back what the document carried rather than a re-sorting of it.
    const reordered = decodeDestructionReceipt(signDestructionReceipt({ ...baseManifest(), reach: [...stated].reverse() }, KEY));
    expect(reordered.manifest.reach.map((one) => one.class).join(',')).toBe('handout,backup,export,pack,store');
  });

  it('states a reach per class and keeps the one class the format declares out of reach unstated as reached', () => {
    const decoded = decodeDestructionReceipt(HONEST);
    const handout = decoded.manifest.reach.find((one) => one.class === 'handout');
    expect(handout?.outcome).toBe(DESTRUCTION_REACH_NOT_REACHED);
    expect(DESTRUCTION_UNREACHABLE_COPY_CLASSES).toEqual(['handout']);
  });

  it('is verified by a reader that holds no object, and reports which half it could not check', () => {
    const verified = verifyDestructionReceipt(HONEST, readWith());
    expect(verified.outcome.objectSha256).toBeUndefined();
    expect(verified.outcome.objectKind).toBeUndefined();
    expect(toHex(verified.outcome.signer)).toBe(toHex(KEY.kid));
    expect(toHex(verified.outcome.destroyed)).toBe(toHex(DESTROYED.kid));
    expect(verified.outcome.destroyed).not.toEqual(verified.outcome.signer);
  });

  it('is verified by a reader that holds the designated bytes, and names both recomputations', () => {
    const verified = verifyDestructionReceipt(HONEST, readWith({ objectBytes: REDACTION_BYTES }));
    expect(toHex(verified.outcome.objectSha256 ?? new Uint8Array())).toBe(toHex(destructionObjectDigest(REDACTION_BYTES)));
    expect(verified.outcome.objectKind).toBe(REDACTION_CONTENT_TYPE);
  });

  it('resolves the key through a resolver as well as through a pinned public key', () => {
    expect(thrownCode(() => verifyDestructionReceipt(HONEST, { resolveKey: (kid) => (toHex(kid) === toHex(KEY.kid) ? KEY.publicKey : undefined) }))).toBe('accepted');
    expect(thrownCode(() => verifyDestructionReceipt(HONEST, { resolveKey: () => undefined }))).toBe('DESTRUCTION_RECEIPT_UNKNOWN_KEY');
  });
});

describe('the writer refuses what it cannot represent', () => {
  it('refuses to seal a reach past the limit the format sets for itself', () => {
    expect(thrownCode(() => signDestructionReceipt(baseManifest({ reach: reachTable({ handout: DESTRUCTION_REACH_REACHED }) }), KEY))).toBe('DESTRUCTION_RECEIPT_REACH_OVERREACH');
    // The encoder is published on its own, so the writer's refusal is witnessed there as well: a caller who
    // builds the bytes without `signDestructionReceipt` meets the same answer at the point the map is written,
    // rather than producing bytes only a reader can refuse.
    expect(thrownCode(() => encodeDestructionReceiptManifest(baseManifest({ reach: reachTable({ handout: DESTRUCTION_REACH_REACHED }) })))).toBe('DESTRUCTION_RECEIPT_REACH_OVERREACH');
  });

  it('refuses to seal a statement under the key it names as destroyed', () => {
    expect(thrownCode(() => signDestructionReceipt(baseManifest({ key: KEY.kid }), KEY))).toBe('DESTRUCTION_RECEIPT_KEY_IS_SIGNER');
  });

  it('refuses a key whose kid is not sha256 of its public half, and one of the wrong width', () => {
    expect(thrownCode(() => signDestructionReceipt(baseManifest(), { ...KEY, kid: new Uint8Array(32).fill(9) }))).toBe('BAD_SIGNING_KEY');
    expect(thrownCode(() => signDestructionReceipt(baseManifest(), { ...KEY, publicKey: new Uint8Array(31) }))).toBe('BAD_SIGNING_KEY');
  });

  it('refuses a manifest its own reader would refuse, before a byte is signed', () => {
    expect(thrownCode(() => signDestructionReceipt(baseManifest({ reach: reachTable().slice(0, 4) }), KEY))).toBe('DESTRUCTION_RECEIPT_MISSING_COPY_CLASS');
    expect(thrownCode(() => signDestructionReceipt(baseManifest({ kind: 'ashaveri/unknown' as never }), KEY))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => signDestructionReceipt(baseManifest({ object: new Uint8Array(31) }), KEY))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });
});

describe('the strict reader refuses every shape the contract does not define', () => {
  it('refuses a member the layout does not define, in the manifest and in one reach entry alike', () => {
    for (const member of ['material', 'publicKey', 'seed', 'copies', 'complete', 'reason', 'reduced']) {
      expect(
        thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set(member, new Uint8Array(64))))),
        `${member} was read as a member of the format`,
      ).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    }
    expect(
      thrownCode(() =>
        decodeDestructionReceipt(
          mutant((root) => {
            const first = (root.get('reach') as Map<unknown, unknown>[])[0]!;
            first.set('material', new Uint8Array(64));
          }),
        ),
      ),
      'a reach entry grew a member',
    ).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect([...DESTRUCTION_RECEIPT_MANIFEST_MEMBERS]).toEqual(['v', 'at', 'object', 'kind', 'key', 'reach', 'states']);
    expect([...DESTRUCTION_RECEIPT_ENTRY_MEMBERS]).toEqual(['class', 'outcome']);
    // A number that is not a whole number cannot reach a check as the integer it imitates, so the reading
    // refuses it before any field is looked at, in a key as much as in a value.
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set(1.5, 1))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('kind', 1.5))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });

  it('refuses an absent member at every required position', () => {
    for (const member of DESTRUCTION_RECEIPT_MANIFEST_MEMBERS) {
      expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.delete(member)))), `${member} was optional`).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    }
  });

  it('refuses a version the format does not declare, and a version that is not an integer', () => {
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('v', 2))))).toBe('DESTRUCTION_RECEIPT_UNSUPPORTED_VERSION');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('v', 0))))).toBe('DESTRUCTION_RECEIPT_UNSUPPORTED_VERSION');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('v', 1.5))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('v', '1'))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });

  it('refuses a bstr at either digest position that is not the one width the format writes', () => {
    // The two positions are the only ones a byte string goes into, so this is the check that keeps a key, a
    // seed or an exported keypair out of the document rather than a rule about what a member is called.
    for (const width of [31, 33, 64]) {
      expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('key', new Uint8Array(width))))), `key at ${String(width)}`).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
      expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('object', new Uint8Array(width))))), `object at ${String(width)}`).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    }
  });

  it('refuses a document kind outside the registry the format enumerates', () => {
    for (const kind of ['ashaveri/deployment-manifest', 'ashaveri/anchor-provenance', 'ashaveri/destruction-receipt', 'receipt', '']) {
      expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('kind', kind)))), `${kind} was a known kind`).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    }
    expect([...DESTRUCTION_OBJECT_KINDS]).not.toContain('ashaveri/destruction-receipt');
  });

  it('refuses a copy class outside the registry, and one named twice', () => {
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => {
      const entries = root.get('reach') as Map<unknown, unknown>[];
      entries[0]!.set('class', 'inbox');
    })))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => {
      const entries = root.get('reach') as Map<unknown, unknown>[];
      entries[1]!.set('class', entries[0]!.get('class'));
    })))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });

  it('refuses a copy class the record says nothing about, at every one of the five', () => {
    // The document is complete-looking at each of these, which is the whole point of the refusal: a reach list
    // that omits `backup` states, to anyone holding it, a destruction that reached what it named.
    for (const name of DESTRUCTION_COPY_CLASSES) {
      const dropped = DESTRUCTION_COPY_CLASSES.filter((one) => one !== name).map(
        (one) => ({ class: one, outcome: DESTRUCTION_REACH_NOT_REACHED }) satisfies DestructionReachEntry,
      );
      expect(
        thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('reach', dropped.map((one) => new Map<string, unknown>([['class', one.class], ['outcome', one.outcome]])))))),
        `${name} was allowed to go unstated`,
      ).toBe('DESTRUCTION_RECEIPT_MISSING_COPY_CLASS');
    }
  });

  it('refuses a reach claim at the class no act of this deployment reaches', () => {
    expect(
      thrownCode(() =>
        decodeDestructionReceipt(
          mutant((root) => root.set('reach', reachTable({ handout: DESTRUCTION_REACH_REACHED }).map((one) => new Map<string, unknown>([['class', one.class], ['outcome', one.outcome]])))),
        ),
      ),
    ).toBe('DESTRUCTION_RECEIPT_REACH_OVERREACH');
    // The other four are inside a deployment's reach and stating them reached is read, not refused.
    for (const name of DESTRUCTION_COPY_CLASSES.filter((one) => !DESTRUCTION_UNREACHABLE_COPY_CLASSES.includes(one))) {
      expect(
        thrownCode(() =>
          decodeDestructionReceipt(
            mutant((root) => root.set('reach', reachTable({ [name]: DESTRUCTION_REACH_REACHED }).map((one) => new Map<string, unknown>([['class', one.class], ['outcome', one.outcome]])))),
          ),
        ),
        `${name} was refused a reach this format allows`,
      ).toBe('accepted');
    }
  });

  it('refuses an outcome that is neither of the two the format declares, in any spelling', () => {
    for (const outcome of [0, 3, true, 'reached']) {
      expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => {
        (root.get('reach') as Map<unknown, unknown>[])[0]!.set('outcome', outcome);
      }))), `outcome ${String(outcome)}`).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    }
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => {
      (root.get('reach') as Map<unknown, unknown>[])[0]!.set('outcome', 1.5);
    })))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });

  it('refuses a reach that is not a list, and a list with nothing in it', () => {
    for (const value of [new Map(), 'store', 1, new Uint8Array(4)]) {
      expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('reach', value))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    }
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('reach', []))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('reach', [new Uint8Array(1)]))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });

  it('refuses a stamp before the epoch and a stamp that is not a whole number', () => {
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('at', -1))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('at', AT + 0.5))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('at', 'now'))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
  });

  it('refuses a sentence that is empty, past its ceiling, or carrying a character that forges a printed line', () => {
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('states', ''))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('states', 'x'.repeat(2049)))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('states', 'erased\u0000 entirely'))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('states', 'erased \u202E entirely'))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('states', new Uint8Array(4)))))).toBe('DESTRUCTION_RECEIPT_BAD_MANIFEST');
    expect(thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('states', 'x'.repeat(683)))))).toBe('accepted');
  });

  it('refuses a receipt sealed by the kid it names as destroyed, whoever signed it', () => {
    const selfSealed = sealedUnder(
      encodeDestructionReceiptProtectedHeader(DESTROYED.kid),
      encodeDestructionReceiptManifest(baseManifest({ key: DESTROYED.kid })),
      DESTROYED,
    );
    expect(thrownCode(() => decodeDestructionReceipt(selfSealed))).toBe('DESTRUCTION_RECEIPT_KEY_IS_SIGNER');
    expect(thrownCode(() => verifyDestructionReceipt(selfSealed, { publicKey: DESTROYED.publicKey }))).toBe('DESTRUCTION_RECEIPT_KEY_IS_SIGNER');
  });

  it('refuses the other five containers at the header, before any key is consulted', () => {
    expect(thrownCode(() => decodeDestructionReceipt(REDACTION_BYTES))).toBe('DESTRUCTION_RECEIPT_BAD_HEADER');
    expect(thrownCode(() => decodeDestructionReceipt(sealedUnder(headerWith((map) => map.set(3, 'ashaveri/pack')), encodeDestructionReceiptManifest(baseManifest()))))).toBe('DESTRUCTION_RECEIPT_BAD_HEADER');
    expect(thrownCode(() => decodeDestructionReceipt(HONEST.slice(0, 20)))).toBe('DESTRUCTION_RECEIPT_MALFORMED_CBOR');
    expect(thrownCode(() => decodeDestructionReceipt(encodeCanonical([])))).toBe('NOT_COSE_SIGN1');
    expect(thrownCode(() => decodeDestructionReceipt(sealedUnder(headerWith((map) => map.set(1, -7)), encodeDestructionReceiptManifest(baseManifest()))))).toBe('UNSUPPORTED_ALG');
    expect(thrownCode(() => decodeDestructionReceipt(sealedUnder(encodeCanonical(new Map<number, unknown>([[1, -8], [4, KEY.kid]])), encodeDestructionReceiptManifest(baseManifest()))))).toBe('DESTRUCTION_RECEIPT_BAD_HEADER');
    expect(thrownCode(() => decodeDestructionReceipt(sealedUnder(headerWith((map) => map.set(9, 1)), encodeDestructionReceiptManifest(baseManifest()))))).toBe('DESTRUCTION_RECEIPT_BAD_HEADER');
    expect(thrownCode(() => decodeDestructionReceipt(sealedUnder(headerWith((map) => map.set(4, new Uint8Array(31))), encodeDestructionReceiptManifest(baseManifest()))))).toBe('DESTRUCTION_RECEIPT_BAD_HEADER');
  });
});

describe('the verifying door', () => {
  it('refuses a call that hands no key, before a byte is read', () => {
    expect(thrownCode(() => verifyDestructionReceipt(mutant((root) => root.set('v', 2)), {}))).toBe('DESTRUCTION_RECEIPT_UNKNOWN_KEY');
  });

  it('refuses another key and an edited document separately', () => {
    expect(thrownCode(() => verifyDestructionReceipt(HONEST, readWith({ publicKey: DESTROYED.publicKey })))).toBe('DESTRUCTION_RECEIPT_KID_MISMATCH');
    const otherKey = signingKeyFromSeed(new Uint8Array(32).fill(43));
    const edited = mutant(() => undefined, otherKey);
    expect(thrownCode(() => verifyDestructionReceipt(edited, readWith()))).toBe('DESTRUCTION_RECEIPT_KID_MISMATCH');
    const elements = decodeCanonical(HONEST) as unknown as { contents: unknown[] };
    const sameKeyButSignatureMoved = sealDestructionReceipt(
      elements.contents[0] as Uint8Array,
      elements.contents[2] as Uint8Array,
      new Uint8Array(64),
    );
    expect(thrownCode(() => verifyDestructionReceipt(sameKeyButSignatureMoved, readWith()))).toBe('INVALID_SIGNATURE');
  });

  it('refuses bytes that are not the object the receipt designates', () => {
    const other = signRedaction(
      { v: 1, at: AT, pack: new Uint8Array(32).fill(7), removed: ['receipt-2'], reduced: new Uint8Array(32).fill(9), states: 'another removal' },
      KEY,
    );
    expect(thrownCode(() => verifyDestructionReceipt(HONEST, readWith({ objectBytes: other })))).toBe('DESTRUCTION_RECEIPT_OBJECT_MISMATCH');
  });

  it('refuses a designation that matches and a kind that does not', () => {
    // Two ways the type claim fails, and both are the same finding: the bytes are the designated ones and they
    // are not the document the receipt calls them. The first is another signed container, the second is not a
    // signed container at all, and the reader answers both rather than reporting a shape fault in a receipt
    // that is whole.
    const namedAsAPack = signDestructionReceipt(baseManifest({ kind: 'ashaveri/pack' }), KEY);
    expect(thrownCode(() => verifyDestructionReceipt(namedAsAPack, readWith({ objectBytes: REDACTION_BYTES })))).toBe('DESTRUCTION_RECEIPT_KIND_DISAGREES');
    const opaque = new TextEncoder().encode('bytes that are no signed document');
    const namedOpaque = signDestructionReceipt(baseManifest({ object: destructionObjectDigest(opaque) }), KEY);
    expect(thrownCode(() => verifyDestructionReceipt(namedOpaque, readWith({ objectBytes: opaque })))).toBe('DESTRUCTION_RECEIPT_KIND_DISAGREES');
    expect(thrownCode(() => verifyDestructionReceipt(HONEST, readWith({ objectBytes: new Uint8Array(32) })))).toBe('DESTRUCTION_RECEIPT_OBJECT_MISMATCH');
  });

  it('states both recomputations on the outcome and never merges the signer with the destroyed key', () => {
    const verified = verifyDestructionReceipt(HONEST, readWith({ objectBytes: REDACTION_BYTES }));
    expect(toHex(verified.outcome.objectSha256 ?? new Uint8Array())).not.toBe(toHex(verified.outcome.destroyed));
    expect(verified.outcome.reach.map((one) => one.class).join(',')).toBe('store,pack,export,backup,handout');
  });
});

describe('the published format and the reader that runs it', () => {
  it('closes the manifest, each reach entry and the header against the blocks that declare them', () => {
    const cddl = readFileSync(CDDLPATH, 'utf8');
    expect([...DESTRUCTION_RECEIPT_MANIFEST_MEMBERS]).toEqual(declaredMembers(cddl, 'Ashaveri-Destruction-Receipt-Manifest'));
    expect([...DESTRUCTION_RECEIPT_ENTRY_MEMBERS]).toEqual(declaredMembers(cddl, 'reach-entry'));
    expect(cddlRule(cddl, 'Ashaveri-Destruction-Receipt-Manifest')).not.toContain('...');
    expect(cddlRule(cddl, 'reach-entry')).not.toContain('...');
    expect(headerLabels(cddl)).toEqual([1, 3, 4]);
    expect(cddl).toContain(`"${DESTRUCTION_RECEIPT_CONTENT_TYPE}"`);
    expect(cddl).toContain('#6.18(COSE_Sign1-Destruction-Receipt-COSE)');
    for (const name of DESTRUCTION_COPY_CLASSES) expect(cddl, `the CDDL never names the class ${name}`).toContain(`"${name}"`);
    for (const kind of DESTRUCTION_OBJECT_KINDS) expect(cddl, `the CDDL never names the kind ${kind}`).toContain(`"${kind}"`);
    for (const member of DESTRUCTION_RECEIPT_MANIFEST_MEMBERS) {
      expect(cddl, `the CDDL never declares ${member}`).toContain(`${member}:`);
    }
  });

  it('declares one version, in the CDDL, in the reader and in the twin alike', () => {
    const cddl = readFileSync(CDDLPATH, 'utf8');
    expect(cddlRule(cddl, 'Ashaveri-Destruction-Receipt-Manifest')).toMatch(/^\s{4}v: 1,/mu);
    expect(declaredMembers(cddl, 'Ashaveri-Destruction-Receipt-Manifest').length).toBe(DESTRUCTION_RECEIPT_MANIFEST_MEMBERS.length);
    expect(JSON.parse(readFileSync(SCHEMAPATH, 'utf8')).$defs?.manifest?.properties?.v).toMatchObject({ const: 1 });
  });
});

describe('the JSON twin of the manifest', () => {
  const schema = JSON.parse(readFileSync(SCHEMAPATH, 'utf8')) as Record<string, unknown>;
  const validate = new Ajv2020({ strict: true }).compile(schema);
  const payload = {
    v: 1,
    at: AT,
    object: toHex(destructionObjectDigest(REDACTION_BYTES)),
    kind: 'ashaveri/redaction',
    key: toHex(DESTROYED.kid),
    reach: reachTable({ store: DESTRUCTION_REACH_REACHED }).map((one) => ({ class: one.class, outcome: one.outcome })),
    states: STATES,
  };
  const projection = {
    protectedHeader: { alg: 'EdDSA', kid: toHex(KEY.kid), typ: DESTRUCTION_RECEIPT_CONTENT_TYPE },
    payload,
  };

  it('compiles under strict mode and closes the maps the writer writes', () => {
    expect(validate(projection), JSON.stringify(validate.errors)).toBe(true);
    const negative: Array<[string, Record<string, unknown>]> = [
      ['a member the format does not define', { ...payload, seed: 'aa'.repeat(32) }],
      ['a reach entry with a member of its own', { ...payload, reach: [{ class: 'store', outcome: 1, material: 'aa' }, ...payload.reach.slice(1)] }],
      ['a copy class outside the registry', { ...payload, reach: [{ class: 'inbox', outcome: 1 }, ...payload.reach.slice(1)] }],
      ['a reach claimed at the class beyond reach', { ...payload, reach: payload.reach.map((one) => (one.class === 'handout' ? { ...one, outcome: 1 } : one)) }],
      ['a document kind outside the registry', { ...payload, kind: 'ashaveri/destruction-receipt' }],
      ['a designation of another width', { ...payload, object: 'deadbeef' }],
      ['a stamp that is not a whole number', { ...payload, at: AT + 0.5 }],
      ['a version that is not this one', { ...payload, v: 2 }],
    ];
    for (const [name, edited] of negative) {
      // The over-reach row is the one the twin cannot refuse and the reader can: JSON Schema sees two
      // well-typed entries and no relation between a class and an outcome, so this case is refused by the
      // `const` pair below rather than by the twin, and the twin says so in prose.
      if (name === 'a reach claimed at the class beyond reach') continue;
      expect(validate({ ...projection, payload: edited }), `${name} was accepted by the twin`).toBe(false);
    }
    for (const member of DESTRUCTION_RECEIPT_MANIFEST_MEMBERS) {
      const without: Record<string, unknown> = { ...payload };
      delete without[member];
      expect(validate({ ...projection, payload: without }), `${member} was not required by the twin`).toBe(false);
    }
    expect(readFileSync(SCHEMAPATH, 'utf8')).toContain('"outcome": { "enum": [1, 2]');
  });

  it('carries floors and no ceiling, which is the sentence the projection states', () => {
    const text = readFileSync(SCHEMAPATH, 'utf8');
    for (const keyword of ['maxLength', 'maxItems', 'maximum', 'exclusiveMaximum']) {
      expect(text, `the twin grew a ${keyword}, which belongs to the CDDL`).not.toContain(keyword);
    }
    expect(text).toContain('the byte ceiling belongs to `destruction-receipt.cddl`');
  });
});

describe('every refusal this container names is reached', () => {
  it('has a case in this file that answers with it', () => {
    const runs: Array<() => string> = [
      () => thrownCode(() => decodeDestructionReceipt(HONEST.slice(0, 20))),
      () => thrownCode(() => decodeDestructionReceipt(encodeCanonical([]))),
      () => thrownCode(() => decodeDestructionReceipt(sealedUnder(headerWith((map) => map.set(9, 1)), encodeDestructionReceiptManifest(baseManifest())))),
      () => thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('v', 2)))),
      () => thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('material', new Uint8Array(64))))),
      () => thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('reach', DESTRUCTION_COPY_CLASSES.filter((one) => one !== 'backup').map((one) => new Map<string, unknown>([['class', one], ['outcome', 2]])))))),
      () => thrownCode(() => decodeDestructionReceipt(mutant((root) => root.set('reach', reachTable({ handout: 1 }).map((one) => new Map<string, unknown>([['class', one.class], ['outcome', one.outcome]])))))),
      () => thrownCode(() => verifyDestructionReceipt(sealedUnder(encodeDestructionReceiptProtectedHeader(DESTROYED.kid), encodeDestructionReceiptManifest(baseManifest({ key: DESTROYED.kid })), DESTROYED), { publicKey: DESTROYED.publicKey })),
      () => thrownCode(() => verifyDestructionReceipt(HONEST, {})),
      () => thrownCode(() => verifyDestructionReceipt(HONEST, readWith({ publicKey: DESTROYED.publicKey }))),
      () => thrownCode(() => verifyDestructionReceipt(HONEST, readWith({ objectBytes: signRedaction({ v: 1, at: AT, pack: new Uint8Array(32).fill(1), removed: ['x'], reduced: new Uint8Array(32).fill(2), states: 'other' }, KEY) }))),
      () => thrownCode(() => verifyDestructionReceipt(signDestructionReceipt(baseManifest({ kind: 'ashaveri/pack' }), KEY), readWith({ objectBytes: REDACTION_BYTES }))),
      () => thrownCode(() => decodeRedaction(HONEST)),
    ];
    const observed = new Set(runs.map((run) => run()));
    for (const one of observed) {
      expect(one, 'a case answered with something no registry declares').not.toMatch(/^UNCODED/);
    }
    const declared = [
      ...new Set([...readFileSync(ERRORSPATH, 'utf8').matchAll(/'(DESTRUCTION_RECEIPT_[A-Z0-9_]+)'/gu)].map((found) => found[1]!)),
    ];
    expect(declared.length, 'this family grew or shrank without its cases').toBeGreaterThanOrEqual(11);
    for (const code of declared) {
      expect(observed, `${code} is declared and no case here reaches it`).toContain(code);
    }
  });
});

/** The text of one CDDL rule of this format, from its opening brace to the line that closes it. */
function cddlRule(cddl: string, rule: string): string {
  const start = cddl.indexOf(`${rule} = {`);
  if (start < 0) throw new Error(`${rule} is not declared in destruction-receipt.cddl`);
  const end = cddl.indexOf('\n}', start);
  if (end < 0) throw new Error(`${rule} in destruction-receipt.cddl never closes`);
  return cddl.slice(start, end);
}

/** The members one block declares by text label, in the order it declares them, comments stripped. */
function declaredMembers(cddl: string, rule: string): string[] {
  const members: string[] = [];
  for (const line of cddlRule(cddl, rule).split('\n').slice(1)) {
    for (const piece of line.split(';')[0]!.split(',')) {
      const found = /^\s*([a-z][a-z0-9_]*)\s*:/u.exec(piece);
      if (found?.[1] !== undefined) members.push(found[1]);
    }
  }
  return members;
}

/** The integer labels one header block declares, sorted, which is what the closure of a signed map turns on. */
function headerLabels(cddl: string): number[] {
  const labels: number[] = [];
  for (const line of cddlRule(cddl, 'Ashaveri-Destruction-Receipt-Protected-Header').split('\n').slice(1)) {
    const found = /^\s*(\d+)\s*:/u.exec(line);
    if (found?.[1] !== undefined) labels.push(Number(found[1]));
  }
  return labels.sort((a, b) => a - b);
}
