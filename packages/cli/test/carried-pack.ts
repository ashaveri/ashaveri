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
  type PackAttachedObject,
  type PackCustodyEntry,
  type PackManifest,
  type ReceiptPayload,
  type SigningKey,
} from '@ashaveri/receipt';

/**
 * Packs that refer to material, and the sealed receipts whose anchors name it.
 *
 * `verify-handover` weighs what a pack refers to, so the cases that exercise that path need a container whose
 * `held` slot digests an object the same container either attaches or leaves a deployment to reach for itself.
 * Neither published fixture serves: the row that refers to material by name attaches nothing beside its
 * references, and the row that attaches a served pair is signed by a vendor whose root its file does not publish,
 * while a case that weighs anything has to hand `--intel-root` a certificate it holds. These builders make both
 * shapes out of the pieces the format package publishes and under the key the fixtures publish their receipts
 * under, and the vendor beside them is generated in the run that pins it, so the only hand-written thing is which
 * digest a slot states.
 *
 * A pack that seals a receipt stating a `held` slot owes that slot a reference, whether or not it attaches the
 * material the slot digests, so `packManifestOf` writes one per held slot rather than taking them as an argument:
 * a builder that left the list out would be unable to seal anything at all, and one that took it as an argument
 * would let a case state a reference for a slot its own receipt does not name, which is a fault the cases below
 * raise on purpose and by moving one position of a manifest they were handed.
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

/** sha256 as bytes, for the digests a slot states and an attached object hashes to. */
export function digestOf(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

/** sha256 as lowercase hex, which is how the command prints a digest. */
export function digestHexOf(bytes: Uint8Array): string {
  return Array.from(digestOf(bytes), (one) => one.toString(16).padStart(2, '0')).join('');
}

/** One anchor slot holding the material, as the receipt states it and the pack refers to it. */
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

/**
 * One entry of the byte arm: the material and the digest the reader recomputes rather than trusts.
 *
 * `chain` is the issuer-chain header as it arrived beside that body and `chainSha256` its digest, and the format
 * pairs the two: an entry carrying a header while stating no digest for it, or the reverse, is a document
 * contradicting itself about a member of its own arm. Both are null here because the material these builders
 * attach arrives as a body alone, which is also what the reference below states; a case that wants the pair hands
 * the header as the second argument, and `servedCarriedPack` below is the one that does. No path a deployment runs
 * fills the arm, so a pack a deployment assembles attaches nothing, and the arm reaches a reader through the
 * published row that hands a pair, the cases that fill it here, and the refusals it owes.
 */
export function attachedObject(bytes: Uint8Array, chain: Uint8Array | null = null): PackAttachedObject {
  return { bytes, sha256: digestOf(bytes), chain, chainSha256: chain === null ? null : digestOf(chain) };
}

/**
 * The origin, the request and the cache key one reference states.
 *
 * A reference names the read it stands behind rather than performing it: nothing in the container looks an origin
 * up, which is why `o` carries no check at this layer, and a deployment that attaches nothing still states the
 * same three figures about a capture it made. These are the shape such a statement has, spelled once for every
 * container built here, and a case that wants a reference disagreeing with the slot it answers for moves the one
 * member it names through `referenceOf`'s `over`.
 */
const READ_ORIGIN = 'intel-tcb-info';
const READ_REQUEST = 'https://api.trustedservices.intel.com/tdx/certification/v4/tcb';

/**
 * The reference one `held` slot of one sealed receipt owes the pack that seals it.
 *
 * Every figure is one a case can recompute from the document beside it: `b` is the digest the slot itself states,
 * `s` and both ends of `w` are read off the stamp the naming record was chained at, and `c` is null beside an arm
 * entry that carries no header, which is the pairing the format weighs. `i` and `n` are null because the material
 * these builders hand is a sentence rather than a document naming an identity or a bound of its own, and an
 * absence is what the format states for a document that states nothing.
 */
export function referenceOf(
  item: string,
  slot: 'col' | 'val',
  digest: Uint8Array,
  at: number,
  over: Partial<PackCustodyEntry> = {},
): PackCustodyEntry {
  return {
    k: { item, slot },
    o: READ_ORIGIN,
    u: READ_REQUEST,
    i: null,
    s: at,
    n: null,
    b: digest,
    c: null,
    a: 'embedded',
    w: { from: at - 60, to: at + 60 },
    y: `${READ_ORIGIN}/${item}/${slot}`,
    ...over,
  };
}

/** The slots one sealed receipt states a digest for, in the order the container names its two halves. */
function heldSlotsOf(receipt: Uint8Array): readonly { readonly slot: 'col' | 'val'; readonly sha256: Uint8Array }[] {
  // A receipt that does not decode states no slot to anything that reads it, and the format's own reader takes
  // the same narrower reading: the document is refused for what it is, and no reference is owed against a digest
  // nobody could read out of it. So the case that seals one gets the refusal it asks for rather than a builder
  // that stops before the command is reached.
  try {
    const { cva } = decodeReceipt(receipt).payload;
    const halves: readonly (readonly ['col' | 'val', CollateralSlot])[] = [
      ['col', cva.collateral],
      ['val', cva.validity],
    ];
    return halves.flatMap(([slot, value]) => (value.presence === 'held' ? [{ slot, sha256: value.sha256 }] : []));
  } catch {
    return [];
  }
}

/** One sealed receipt, named as the pack names it and chained under `iat`. */
export interface PackEntry {
  readonly id: string;
  readonly iat: number;
  readonly receipt: Uint8Array;
}

/**
 * A pack sealing these receipts, referring to every slot they state a digest for and attaching this material.
 *
 * The relations the reader checks are the ones `verify-pack` reports on: the span around the stamps, `at` after
 * the span closes, the duty revision behind the reads and `held` covering the oldest record. The figures are
 * computed from the entries handed in so a case states only which receipts it seals and which objects it attaches.
 * `referenceOver` moves a member of every reference the same way, which is how a container whose material arrived
 * beside a chain header states that: the arm entry carries the header, and the reference beside it owes its digest.
 */
export function packOf(
  entries: readonly PackEntry[],
  attached: readonly PackAttachedObject[],
  referenceOver: Partial<PackCustodyEntry> = {},
): Uint8Array {
  return signPack(packManifestOf(entries, attached, referenceOver), RECEIPT_KEY);
}

/**
 * The manifest these entries and this material amount to, before anything seals it.
 *
 * Published separately from `packOf` because an arm that contradicts the slots it answers for is a manifest
 * `signPack` refuses, and the document a deployment would have to assemble by hand to publish one is the document
 * the reader exists to answer. The cases that need it take this object, move the one position their row names,
 * and seal the result below.
 */
export function packManifestOf(
  entries: readonly PackEntry[],
  attached: readonly PackAttachedObject[],
  referenceOver: Partial<PackCustodyEntry> = {},
): PackManifest {
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
  const custody = entries.flatMap((one) =>
    heldSlotsOf(one.receipt).map((slot) => referenceOf(one.id, slot.slot, slot.sha256, one.iat, referenceOver)),
  );
  return {
    v: 1,
    at,
    span: { from, to },
    chain: { anchor: new Uint8Array(32), head: previous },
    duty: { art: 'retention-evidence', rev: at - 10, required: 31_536_000, held: at - from },
    items,
    custody,
    attached,
  };
}

/**
 * A pack assembled from the pieces the format publishes, over a manifest the writer would not sign.
 *
 * This is the piecewise path `verify-handover.test.ts` takes for the same reason and the published pack suite
 * documents: an arm entry misstating its own bytes, holding one digest twice, or holding an entry no reference of
 * this pack names is refused by `signPack` before it can be sealed, and only a reader can be handed it. The
 * framing is the writer's own, so the fault a row states is the only difference between these bytes and a
 * document a deployment signs.
 */
export function sealPackManifest(manifest: PackManifest): Uint8Array {
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
 * The shortest container that reaches the weighing: one record, one held slot naming one object, that object
 * attached, and the reference the slot owes beside it. A case that wants two slots or a stated absence builds the
 * pair itself with `anchorReceiptOf`.
 */
export function packAttaching(bytes: Uint8Array, iat: number, id = 'receipt-0'): { readonly pack: Uint8Array; readonly digest: string } {
  const receipt = anchorReceiptOf({ col: held(bytes), val: absent('the collector read no window') }, iat);
  return { pack: packOf([{ id, iat, receipt }], [attachedObject(bytes)]), digest: digestHexOf(bytes) };
}

/**
 * The shortest pack that reaches a weighing through a chain: one record whose `col` slot names a served body, whose
 * `val` slot states an absence, and whose arm carries that body beside the header that arrived with it.
 *
 * This is the served half of the arm, the one `packages/fixtures/data/pack-v1.json` now publishes as
 * `custody-served-weighed` and the one an embedded body can never reach: the material arrives as the wrapper a
 * service answers in, with no certificates inside it, so a reader weighing it needs the header the reference
 * states a digest for and cannot get anywhere without it. The bytes come in as arguments rather than being made
 * here because the vendor that signed them belongs to the caller, which is the half that has to be generated in
 * the run that pins its root; everything after them is the sealing the format package does.
 *
 * `referenceOver` is what says so: `a` is the arm the capture weighed with and `c` is the digest of the header
 * beside the body, and the format refuses an entry carrying a header the reference beside it states no digest
 * for, which is why the two travel together and not as an argument a case can forget. `entries` comes back beside
 * the sealed pack because a case that wants the same container with one position of its arm moved has to move a
 * manifest built from the very record this pack seals, and a second receipt of its own invention would be a
 * different document rather than a disagreement inside this one.
 */
export function servedCarriedPack(body: Uint8Array, chain: Uint8Array, iat: number, id = 'receipt-0'): {
  readonly pack: Uint8Array;
  readonly entries: readonly PackEntry[];
  readonly digest: string;
  readonly chainDigest: string;
  readonly bodyBytes: number;
} {
  const object = attachedObject(body, chain);
  const receipt = anchorReceiptOf({ col: held(body), val: absent('the collector read no window') }, iat);
  const entries: readonly PackEntry[] = [{ id, iat, receipt }];
  return {
    pack: packOf(entries, [object], { a: 'served', c: object.chainSha256 }),
    entries,
    digest: digestHexOf(body),
    chainDigest: digestHexOf(chain),
    bodyBytes: body.byteLength,
  };
}
