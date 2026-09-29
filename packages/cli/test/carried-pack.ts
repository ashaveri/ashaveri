import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  decodeReceipt,
  encodePackManifest,
  encodePackProtectedHeader,
  issueReceipt,
  packRecordDigest,
  packSigStructure,
  sealPack,
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
 * be this file's document rather than the command's. The receipts are issued by `issueReceipt`, so the reader
 * inside the pack check is the shipped one and the anchor slots are read from signed bytes the same way the
 * command reads them.
 */

const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

/** The published receipt signing key, seed and all, which is the key every document here is sealed under. */
const RECEIPT_SEED = (JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as { privateKey: string }).privateKey;

export const RECEIPT_KEY: SigningKey = signingKeyFromSeed(new Uint8Array(Buffer.from(RECEIPT_SEED, 'hex')));

/** The same key as the `--key` designation the command takes. */
export const RECEIPT_PUBLIC_B64URL = Buffer.from(RECEIPT_KEY.publicKey).toString('base64url');

/** The published marked v2 payload, which is the document a `v: 3` receipt here differs from by its members. */
const decoded = decodeReceipt(new Uint8Array(readFileSync(`${DATA}receipts/receipt-marked-v2.cbor`))).payload;
if (decoded.v !== 2) {
  throw new Error(`the published marked vector is not a v2 document but a v${decoded.v} one`);
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

/** A `v: 3` receipt at `iat`, sealing the given anchor pair, signed under the published receipt key. */
export function anchorReceiptOf(slots: HeldPair, iat: number): Uint8Array {
  const payload: ReceiptPayload = {
    ...published,
    v: 3,
    iat,
    mk: published.mk,
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: { collateral: slots.col, validity: slots.val },
    itm: [{ t: iat, d: digestOf(new TextEncoder().encode('the first item of the response')) }],
  };
  return issueReceipt(payload, RECEIPT_KEY);
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
    v: 2,
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
 * A `v: 3` receipt and the one pack that seals it, whose `col` slot names the bytes handed here.
 *
 * The shortest container that reaches the weighing: one record, one held slot naming one object, and the object
 * carried. A case that wants two slots or a stated absence builds the pair itself with `anchorReceiptOf`.
 */
export function packCarrying(bytes: Uint8Array, iat: number, id = 'receipt-0'): { readonly pack: Uint8Array; readonly digest: string } {
  const receipt = anchorReceiptOf({ col: held(bytes), val: absent('the collector read no window') }, iat);
  return { pack: packOf([{ id, iat, receipt }], [carriedObject(bytes)]), digest: digestHexOf(bytes) };
}
