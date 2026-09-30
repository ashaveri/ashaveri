import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  decodeReceipt,
  decodeCanonical,
  encodeCanonical,
  encodePackManifest,
  encodePackProtectedHeader,
  encodePayload,
  packRecordDigest,
  packSigStructure,
  sealPack,
  signCoseSign1,
  signPack,
  signingKeyFromSeed,
  type CollateralSlot,
  type PackCarriedObject,
  type PackManifest,
  type ReceiptPayload,
  type SigningKey,
} from '@ashaveri/receipt';

/**
 * Packs that carry material, and the sealed receipts whose anchors name it.
 *
 * `verify-handover` weighs what a pack carries, so the cases that exercise that path need a container whose
 * `held` slot digests an object the same container carries, and neither document can be one of the published
 * fixtures: every pack vector carries an empty list, and every receipt vector states an absence in both of its
 * anchor slots. These two builders make the shape the fixtures do not hold, out of the pieces the format package
 * publishes and under the key the fixtures publish their receipts under, so the only hand-written thing is which
 * digest a slot states.
 *
 * The pack goes through `signPack` rather than the piecewise framing `verify-handover.test.ts` needs for its
 * fault cases, because every container built here is one the writer signs: a pack the format refuses to seal
 * would not reach the weighing, and a row that reached it because a local framing slipped past the writer would
 * be this file's document rather than the command's. The receipts are laid out by `encodePayload`, so the reader
 * inside the pack check is the shipped one and the anchor slots are read from signed bytes the same way the
 * command reads them. One member is written after that layout and before the signature: the writer refuses an
 * attested text member carrying text that would forge the line it is printed on, and a case whose point is that
 * a reader still has to report such a sentence is about a document this estate will no longer make but another
 * issuer can hand over. `anchorReceiptOf` says which member that is put in afterwards, and why a reader's corpus
 * is the one place it has to be.
 */

const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

/** The published receipt signing key, seed and all, which is the key every document here is sealed under. */
const RECEIPT_SEED = (JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as { privateKey: string }).privateKey;

export const RECEIPT_KEY: SigningKey = signingKeyFromSeed(new Uint8Array(Buffer.from(RECEIPT_SEED, 'hex')));

/** The same key as the `--key` designation the command takes. */
export const RECEIPT_PUBLIC_B64URL = Buffer.from(RECEIPT_KEY.publicKey).toString('base64url');

/** The published marked payload, which is the document the receipts below differ from by one member. */
const decoded = decodeReceipt(new Uint8Array(readFileSync(`${DATA}receipts/receipt-marked-v1.cbor`))).payload;
if (decoded.v !== 1) {
  throw new Error(`the published marked vector is not a v1 document but a v${decoded.v} one`);
}

// Captured in a second name rather than read through the check above: a narrowing of a discriminant does not
// follow a reference into a function body, and every builder below is a function body.
const published = decoded;

/**
 * The published payload, for a case that needs fields a real deployment states rather than ones this file
 * invents: the issuer, the instance, the epoch and the model a manifest row prints are read from here so that
 * the only false thing about a document is the figure the case names.
 */
export const PUBLISHED_PAYLOAD = published;

/** sha256 as bytes, for the digests a slot states and a carried object hashes to. */
export function digestOf(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

/** sha256 as lowercase hex, which is how the command prints a digest. */
export function digestHexOf(bytes: Uint8Array): string {
  return Array.from(digestOf(bytes), (one) => one.toString(16).padStart(2, '0')).join('');
}

/** One anchor slot holding the material, as the receipt states it and the pack carries it. */
export interface HeldPair {
  readonly col: CollateralSlot;
  readonly val: CollateralSlot;
}

/** The `held` arm of a slot: the digest of these exact bytes, which is the only name the pack gives them. */
export function held(bytes: Uint8Array): CollateralSlot {
  return { presence: 'held', sha256: digestOf(bytes) };
}

/** The `absent-at-source` arm, whose reason is the collector's own sentence and nothing else. */
export function absent(reason: string): CollateralSlot {
  return { presence: 'absent-at-source', reason };
}

/** The sentence an absent slot carries when the case hands over one the writer will not sign. */
const PLACEHOLDER_REASON = 'the collector read no window';

/**
 * A receipt at `iat`, sealing the given anchor pair, signed under the published receipt key.
 *
 * The layout is the writer's and the absence reason is put in afterwards, over a placeholder the writer did
 * sign, because the writer refuses to seal text that would forge the line a member is printed on
 * (`assertLineSafeText`, `packages/receipt/src/receipt.ts`). A case that hands this file a reason carrying a
 * newline is not asking for a document this estate would issue; it is asking how a row reads a document it
 * was handed, which is the half that stays open: an older issuer, or software that never read that refusal,
 * signs such bytes today and a verifier has to report them rather than drop them. So the hostile reason
 * arrives below the writer, at the same position and in the same encoding the writer would have used for the
 * placeholder, and nothing about the layout, the ordering or the signature is hand-written here.
 */
export function anchorReceiptOf(slots: HeldPair, iat: number): Uint8Array {
  const payload: ReceiptPayload = {
    ...published,
    iat,
    cva: { collateral: withPlaceholder(slots.col), validity: withPlaceholder(slots.val) },
    itm: [{ t: iat, d: digestOf(new TextEncoder().encode('the first item of the response')) }],
  };
  const laid = decodeCanonical(encodePayload(payload)) as Map<string, unknown>;
  const anchor = laid.get('cva') as Map<string, unknown>;
  for (const [leg, slot] of [['col', slots.col], ['val', slots.val]] as const) {
    if (slot.presence === 'held') continue;
    (anchor.get(leg) as Map<string, unknown>).set('r', slot.reason);
  }
  return signCoseSign1(encodeCanonical(laid), RECEIPT_KEY);
}

/**
 * The slot as the writer will take it: an absent arm carries the placeholder sentence at the layout step, and
 * the case's own words go in after it. Every absent arm is written this way, whether or not its reason would
 * have been refused, so which reason a case chose is never the thing that decides whether a document of the
 * case can be built at all. The measurement is the published one and no case here moves it, which is why
 * laying the payload out and signing the result stands in for the issuing call without dropping a check.
 */
function withPlaceholder(slot: CollateralSlot): CollateralSlot {
  return slot.presence === 'held' ? slot : { presence: slot.presence, reason: PLACEHOLDER_REASON };
}

/** One carried object: the material and the digest the reader recomputes rather than trusts. */
export function carriedObject(bytes: Uint8Array): PackCarriedObject {
  return { bytes, sha256: digestOf(bytes) };
}

/** One sealed receipt, named as the pack names it and chained under `iat`. */
export interface PackEntry {
  readonly id: string;
  readonly iat: number;
  readonly receipt: Uint8Array;
}

/**
 * A pack sealing these receipts and carrying exactly this material.
 *
 * The relations the reader checks are the ones `verify-pack` reports on: the span around the stamps, `at` after
 * the span closes, the duty revision behind the reads and `held` covering the oldest record. The figures are
 * computed from the entries handed in so a case states only which receipts it seals and which objects it carries.
 */
export function packOf(entries: readonly PackEntry[], carried: readonly PackCarriedObject[]): Uint8Array {
  return signPack(packManifestOf(entries, carried), RECEIPT_KEY);
}

/**
 * The manifest these entries and this material amount to, before anything seals it.
 *
 * Published separately from `packOf` because a carried list that contradicts the slots it answers for is a
 * manifest `signPack` refuses, and the document a deployment would have to assemble by hand to publish one is
 * the document the reader exists to answer. The cases that need it take this object, move the one position their
 * row names, and seal the result below.
 */
export function packManifestOf(entries: readonly PackEntry[], carried: readonly PackCarriedObject[]): PackManifest {
  const stamps = entries.map((one) => one.iat);
  const from = Math.min(...stamps);
  const to = Math.max(...stamps) + 1;
  const at = to + 1_000;
  let previous: Uint8Array<ArrayBufferLike> = new Uint8Array(32);
  const items = entries.map((one) => {
    const item = { id: one.id, iat: one.iat, prev: previous, receipt: one.receipt };
    previous = packRecordDigest(item);
    return item;
  });
  return {
    v: 1,
    at,
    span: { from, to },
    chain: { anchor: new Uint8Array(32), head: previous },
    duty: { art: 'retention-evidence', rev: at - 10, required: 31_536_000, held: at - from },
    items,
    carried,
  };
}

/**
 * A pack assembled from the pieces the format publishes, over a manifest the writer would not sign.
 *
 * This is the piecewise path `verify-handover.test.ts` takes for the same reason and the published pack suite
 * documents: a carried list misstating its own bytes, holding one digest twice, holding an entry no slot names,
 * or missing the entry a slot names is refused by `signPack` before it can be sealed, and only a reader can be
 * handed it. The framing is the writer's own, so the fault a row states is the only difference between these
 * bytes and a document a deployment signs.
 */
export function sealCarriedPack(manifest: PackManifest): Uint8Array {
  const payloadBytes = encodePackManifest(manifest);
  const protectedBytes = encodePackProtectedHeader(RECEIPT_KEY.kid);
  const signature = sign(null, packSigStructure(protectedBytes, payloadBytes), privateKeyFromSeed(RECEIPT_SEED));
  return sealPack(protectedBytes, payloadBytes, new Uint8Array(signature));
}

/** The published seed as a key node can take it: the PKCS8 wrapping of an Ed25519 private key. */
function privateKeyFromSeed(seedHex: string): ReturnType<typeof createPrivateKey> {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * A receipt naming held slots and the one pack that seals it, whose `col` slot names the bytes handed here.
 *
 * The shortest container that reaches the weighing: one record, one held slot naming one object, and the object
 * carried. A case that wants two slots or a stated absence builds the pair itself with `anchorReceiptOf`.
 */
export function packCarrying(bytes: Uint8Array, iat: number, id = 'receipt-0'): { readonly pack: Uint8Array; readonly digest: string } {
  const receipt = anchorReceiptOf({ col: held(bytes), val: absent('the collector read no window') }, iat);
  return { pack: packOf([{ id, iat, receipt }], [carriedObject(bytes)]), digest: digestHexOf(bytes) };
}
