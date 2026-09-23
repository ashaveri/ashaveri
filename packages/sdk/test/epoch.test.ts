import { describe, expect, it } from 'vitest';
import { decodeReceipt, toHex } from '@ashaveri/receipt';
import { adjudicateReceiptEpoch } from '../src/epoch.js';
import { SdkError } from '../src/errors.js';
import { parseManifest } from '../src/manifest.js';
import { GatewaySession } from '../src/gateway.js';
import {
  MANIFEST_BASE_URL,
  RECEIPT_KEY,
  ROTATED_KEY,
  STRANGER_KEY,
  keyEntry,
  manifestTransport,
  pinMap,
  plainManifest,
  receiptFor,
} from './manifest-documents.js';

/**
 * What a receipt's own claim about its signing key is worth against the deployment's declaration.
 *
 * A receipt carries its `kid` in the protected header and its `epk` inside the signature, so both are the
 * signer's statement about which key and which moment produced it. The manifest is the deployment's
 * statement about which keys it held in which epochs. Two shapes of that statement exist and the rule
 * answers for both:
 *
 * - `keys[]` with an epoch and a validity start on every entry: a declared rotation history, where a
 *   superseded epoch keeps verifying against the key the deployment retained for it, and only inside the
 *   window that entry opens. The bound is what makes retention safe, because without it a retired key
 *   could sign today's traffic and have the result read as history.
 * - `keys[]` with neither, which is every manifest published before epochs were checked: the one epoch
 *   such a document states is its own `epk`, and the only keys it attributes to it are the ones it lists.
 *
 * Three refusals stay apart on purpose. `MANIFEST_KEY_NOT_PINNED` is about what this client designated,
 * `MANIFEST_EPOCH_UNDECLARED` about an epoch this deployment never claimed, and `MANIFEST_EPOCH_DISAGREES`
 * about a deployment whose claim and this signature do not fit together.
 */

const IAT = 1_772_000_000;
const EARLIER = IAT - 10_000;
const ROTATION_STARTS = IAT + 100;
const NONCE = new Uint8Array(16).fill(0x77);
const RESPONSE_BYTES = new TextEncoder().encode('manifest-seal-response');

/** One key per epoch, the second starting where the first one's window closes. */
const WINDOWS = [
  keyEntry(RECEIPT_KEY, { epk: 1, validFrom: EARLIER }),
  keyEntry(ROTATED_KEY, { epk: 2, validFrom: ROTATION_STARTS }),
];

function documentFor(keys: readonly Record<string, unknown>[], epoch: number) {
  return parseManifest(JSON.parse(new TextDecoder().decode(plainManifest({ keys, epoch }))));
}

async function failureFrom(promise: Promise<unknown>): Promise<SdkError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof SdkError) return err;
    throw err;
  }
  throw new Error('the client accepted a receipt this case expects it to refuse');
}

/** The live path: a session reading one manifest, and one receipt to adjudicate against it. */
async function verifyThrough(
  keys: readonly Record<string, unknown>[],
  receipt: Uint8Array,
  manifestEpoch?: number,
) {
  const payload = decodeReceipt(receipt).payload;
  const session = new GatewaySession(MANIFEST_BASE_URL, {
    fetchImpl: manifestTransport(plainManifest({ keys, epoch: manifestEpoch ?? payload.epk })),
    policy: { issuers: [payload.iss], keys: pinMap(RECEIPT_KEY, ROTATED_KEY) },
  });
  const verified = await session.verifyReceipted({
    receiptBytes: receipt,
    nonce: NONCE,
    requestHash: payload.req,
    responseHash: payload.res,
    responseBytes: RESPONSE_BYTES,
    // Read at the instant it was issued: these cases are about which key held which epoch, and a clock
    // that ran ahead of the receipt would answer a different question with a different code.
    now: payload.iat * 1000,
  });
  const verdict = await session.adjudicateEpoch({
    kid: toHex(verified.header.kid),
    epoch: payload.epk,
    issuedAt: payload.iat,
  });
  return { verified, verdict };
}

describe('the rotation history a manifest declares', () => {
  it('ends each window at the epoch above it and leaves the highest open', () => {
    expect(documentFor(WINDOWS, 2).epochs).toEqual([
      { epoch: 1, validFrom: EARLIER, validTo: ROTATION_STARTS, kids: [toHex(RECEIPT_KEY.kid)] },
      { epoch: 2, validFrom: ROTATION_STARTS, validTo: null, kids: [toHex(ROTATED_KEY.kid)] },
    ]);
  });

  it('groups two keys of one epoch into one window', () => {
    const both = [
      keyEntry(RECEIPT_KEY, { epk: 1, validFrom: EARLIER }),
      keyEntry(ROTATED_KEY, { epk: 1, validFrom: EARLIER }),
    ];
    expect(documentFor(both, 1).epochs).toEqual([
      { epoch: 1, validFrom: EARLIER, validTo: null, kids: [toHex(RECEIPT_KEY.kid), toHex(ROTATED_KEY.kid)] },
    ]);
  });

  it('reads a manifest that names no window as declaring none', () => {
    const parsed = documentFor([keyEntry(RECEIPT_KEY)], 0);
    expect(parsed.epochs).toBeNull();
    expect(parsed.keys).toEqual([
      { kid: toHex(RECEIPT_KEY.kid), alg: 'Ed25519', publicKey: parsed.keys[0]!.publicKey },
    ]);
  });

  it('refuses an entry that names one half of the pair and not the other', () => {
    // One member of the pair states nothing a reader can use, and a start with no epoch is how an
    // endless window gets read by accident.
    const bare = { kid: toHex(RECEIPT_KEY.kid), alg: 'Ed25519', publicKey: 'A'.repeat(43) };
    for (const half of [{ ...bare, epk: 1 }, { ...bare, validFrom: EARLIER }]) {
      expect(() => documentFor([half], 1)).toThrowError(/without a/);
    }
  });

  it('refuses an array whose entries disagree about which shape they have', () => {
    const mixed = [keyEntry(RECEIPT_KEY, { epk: 1, validFrom: EARLIER }), keyEntry(ROTATED_KEY)];
    expect(() => documentFor(mixed, 1)).toThrowError(
      /names no epoch while another key in the same manifest names one/,
    );
  });

  it('refuses one epoch published with two different starts', () => {
    const contradictory = [
      keyEntry(RECEIPT_KEY, { epk: 1, validFrom: EARLIER }),
      keyEntry(ROTATED_KEY, { epk: 1, validFrom: IAT }),
    ];
    expect(() => documentFor(contradictory, 1)).toThrowError(/epoch 1 is declared with two validity starts/);
  });

  it('refuses a history whose epochs do not ascend with their starts', () => {
    // Two windows containing one instant would make the key a receipt is verified under depend on which
    // entry the reader happened to reach first.
    const backwards = [
      keyEntry(RECEIPT_KEY, { epk: 1, validFrom: IAT }),
      keyEntry(ROTATED_KEY, { epk: 2, validFrom: EARLIER }),
    ];
    expect(() => documentFor(backwards, 2)).toThrowError(/epoch 2 starts at .*which is not after epoch 1/);
  });
});

describe('the rule, asked of one manifest at a time', () => {
  const withWindows = documentFor(WINDOWS, 2);
  const legacy = documentFor([keyEntry(RECEIPT_KEY)], 3);
  const claim = (kid: Uint8Array, epoch: number, issuedAt: number) => ({ kid: toHex(kid), epoch, issuedAt });

  it('admits a receipt inside a declared window and says which window did it', () => {
    const verdict = adjudicateReceiptEpoch(withWindows, claim(RECEIPT_KEY.kid, 1, IAT));
    expect(verdict).toMatchObject({
      ok: true,
      basis: 'windows',
      epoch: 1,
      validFrom: EARLIER,
      validTo: ROTATION_STARTS,
      superseded: true,
    });
    if (!verdict.ok) throw new Error('a declared window was refused');
    expect(verdict.detail).toContain('superseded by 2');
  });

  it('admits the current epoch without calling it superseded', () => {
    expect(adjudicateReceiptEpoch(withWindows, claim(ROTATED_KEY.kid, 2, ROTATION_STARTS + 400))).toMatchObject({
      ok: true,
      basis: 'windows',
      epoch: 2,
      superseded: false,
    });
  });

  it('refuses a stamp outside its window, including one exactly at the successor start', () => {
    const tooEarly = adjudicateReceiptEpoch(withWindows, claim(RECEIPT_KEY.kid, 1, EARLIER - 1));
    expect(tooEarly).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_DISAGREES' });
    // The half-open direction is the same one the pack's span takes: a receipt stamped at a successor's
    // start belongs to the successor, so the retained key's window has closed at that instant.
    const atBoundary = adjudicateReceiptEpoch(withWindows, claim(RECEIPT_KEY.kid, 1, ROTATION_STARTS));
    expect(atBoundary).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_DISAGREES' });
    if (atBoundary.ok) throw new Error('a window boundary admitted the wrong side');
    expect(atBoundary.detail).toContain('outside the epoch 1 window');
  });

  it('refuses a key that claims an epoch another key holds', () => {
    const verdict = adjudicateReceiptEpoch(withWindows, claim(ROTATED_KEY.kid, 1, IAT));
    expect(verdict).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_DISAGREES' });
    if (verdict.ok) throw new Error('a key was credited with another key epoch');
    expect(verdict.detail).toContain(toHex(RECEIPT_KEY.kid));
  });

  it('refuses an epoch this manifest never named, and lists the ones it did', () => {
    const verdict = adjudicateReceiptEpoch(withWindows, claim(RECEIPT_KEY.kid, 9, IAT));
    expect(verdict).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_UNDECLARED' });
    if (verdict.ok) throw new Error('an undeclared epoch was admitted');
    expect(verdict.detail).toContain('which publishes 1, 2');
  });

  it('answers with one epoch and every listed key when the manifest declares no windows', () => {
    expect(adjudicateReceiptEpoch(legacy, claim(RECEIPT_KEY.kid, 3, IAT))).toMatchObject({
      ok: true,
      basis: 'current-epoch',
      validFrom: null,
      validTo: null,
      superseded: false,
    });
    const otherEpoch = adjudicateReceiptEpoch(legacy, claim(RECEIPT_KEY.kid, 2, IAT));
    expect(otherEpoch).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_UNDECLARED' });
    if (otherEpoch.ok) throw new Error('an undeclared epoch was admitted beside a manifest with no history');
    expect(otherEpoch.detail).toContain('this manifest declares one epoch, 3');
    expect(adjudicateReceiptEpoch(legacy, claim(STRANGER_KEY.kid, 3, IAT))).toMatchObject({
      ok: false,
      code: 'MANIFEST_EPOCH_DISAGREES',
    });
  });

  it('invents no window for the reading that has none', () => {
    // A zero here would read as a deployment that had published a start and chosen the epoch, which is a
    // claim this manifest does not make.
    const verdict = adjudicateReceiptEpoch(legacy, claim(RECEIPT_KEY.kid, 3, IAT));
    if (!verdict.ok) throw new Error('the only epoch such a manifest states was refused');
    expect([verdict.validFrom, verdict.validTo]).toEqual([null, null]);
  });
});

describe('the rule on the live path', () => {
  it('verifies a receipt signed under a superseded epoch against the retained key', async () => {
    const receipt = receiptFor({ key: RECEIPT_KEY, epoch: 1, issuedAt: IAT, nonce: NONCE });
    const { verified, verdict } = await verifyThrough(WINDOWS, receipt, 2);
    expect(toHex(verified.header.kid)).toBe(toHex(RECEIPT_KEY.kid));
    expect(verdict).toMatchObject({ ok: true, basis: 'windows', superseded: true, epoch: 1 });
  });

  it('verifies for both keys of a rotation while both are live', async () => {
    const before = receiptFor({ key: RECEIPT_KEY, epoch: 1, issuedAt: EARLIER + 1, nonce: NONCE });
    const after = receiptFor({ key: ROTATED_KEY, epoch: 2, issuedAt: ROTATION_STARTS + 1, nonce: NONCE });
    const first = await verifyThrough(WINDOWS, before, 2);
    const second = await verifyThrough(WINDOWS, after, 2);
    expect(toHex(first.verified.header.kid)).toBe(toHex(RECEIPT_KEY.kid));
    expect(toHex(second.verified.header.kid)).toBe(toHex(ROTATED_KEY.kid));
    expect([first.verdict.ok, second.verdict.ok]).toEqual([true, true]);
    if (!first.verdict.ok || !second.verdict.ok) throw new Error('a live key of a rotation was refused');
    expect([first.verdict.superseded, second.verdict.superseded]).toEqual([true, false]);
  });

  it('refuses a retained key signing after its window closed', async () => {
    const late = receiptFor({ key: RECEIPT_KEY, epoch: 1, issuedAt: ROTATION_STARTS + 1, nonce: NONCE });
    const err = await failureFrom(verifyThrough(WINDOWS, late, 2).then((each) => each.verified));
    expect(err.code).toBe('MANIFEST_EPOCH_DISAGREES');
    expect(err.message).toContain('outside the epoch 1 window');
  });

  it('refuses a receipt naming an epoch the deployment never declared', async () => {
    const fromAnotherHistory = receiptFor({ key: RECEIPT_KEY, epoch: 4, issuedAt: IAT, nonce: NONCE });
    const err = await failureFrom(
      verifyThrough([keyEntry(RECEIPT_KEY, { epk: 1, validFrom: EARLIER })], fromAnotherHistory).then(
        (each) => each.verified,
      ),
    );
    expect(err.code).toBe('MANIFEST_EPOCH_UNDECLARED');
    expect(err.message).toContain('claims epoch 4');
  });

  it('refuses a past-epoch receipt against the manifest a deployment serves today', async () => {
    // No windows, one key, one epoch: the shape every manifest published before this rule landed carries,
    // and the one that still refuses a receipt from an epoch it says nothing about.
    const old = receiptFor({ key: RECEIPT_KEY, epoch: 7, issuedAt: IAT, nonce: NONCE });
    const err = await failureFrom(verifyThrough([keyEntry(RECEIPT_KEY)], old, 0).then((each) => each.verified));
    expect(err.code).toBe('MANIFEST_EPOCH_UNDECLARED');
    expect(err.message).toContain('this manifest declares one epoch, 0');
  });

  it('verifies a receipt at the epoch a windowless manifest states', async () => {
    const served = receiptFor({ key: RECEIPT_KEY, epoch: 0, issuedAt: IAT, nonce: NONCE });
    const { verdict } = await verifyThrough([keyEntry(RECEIPT_KEY)], served);
    expect(verdict).toMatchObject({ ok: true, basis: 'current-epoch', superseded: false });
  });
});
