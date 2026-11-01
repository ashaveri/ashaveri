import { ReceiptError } from './errors.js';
import type { CollateralSlot, StampDisclosure } from './disclosure.js';
import { isReceiptVersion } from './receipt.js';
import type { Encryption, ItemStamp, Marking, ReceiptPayload } from './receipt.js';
import { decodeReceipt } from './receipt.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The twelve fields every payload carries, in the projection this file defines. `v` sits beside them in the
 * two shapes below, because the version is what tells a reader which format these bytes were signed under,
 * and this build reads two.
 */
interface ReceiptFieldsJson {
  iss: string;
  ins: string;
  iat: number;
  nce: string;
  req: string;
  res: string;
  mdl: string;
  wts: string;
  meas: { tee: string; m: string };
  att: { d: string; ts: number; url: string };
  epk: number;
  tok: { p: number; c: number };
}

/** The two arms of one anchor slot, spelled as the format spells them: a label, then a digest or a reason. */
type CollateralSlotJson = { p: 'held'; d: string } | { p: 'absent-at-source' | 'not-taken-in'; r: string };

/**
 * The two arms of `enc`, spelled as the format spells them: a label, then the key only the session arm has a
 * use for. `sch` is a registry label rather than an enumerated one here as it is in the twin schema, because
 * which labels a reader can interpret is the registry's answer and not this projection's.
 */
type EncryptionJson = { sch: 'none' } | { sch: string; pk: string };

/** The disclosure of one stamped instant, with its `null` kept as `null` rather than dropped. */
interface StampDisclosureJson {
  name: string;
  unc: number | null;
}

/** The members a version 1 payload states about its own issuance, in the order the format lists them. */
interface StatedMembersJson {
  mk: { sch: string; d: string };
  sd: StampDisclosureJson;
  cva: { col: CollateralSlotJson; val: CollateralSlotJson };
  itm: Array<{ t: number; d: string }>;
}

/** Version 1's payload: the twelve shared fields, then the mark, the disclosure, the anchor and the items. */
export interface ReceiptPayloadV1Json extends ReceiptFieldsJson, StatedMembersJson {
  v: 1;
}

/**
 * Version 2's payload: the same seventeen positions and `enc` appended, in the place the format lists it, so
 * the difference between the two projections is the one member the version exists to carry.
 */
export interface ReceiptPayloadV2Json extends ReceiptFieldsJson, StatedMembersJson {
  v: 2;
  enc: EncryptionJson;
}

/** The one payload this projection writes, whichever version the document names. */
export type ReceiptPayloadJson = ReceiptPayloadV1Json | ReceiptPayloadV2Json;

export interface ReceiptJson {
  protectedHeader: { alg: string; kid: string; typ: string };
  payload: ReceiptPayloadJson;
  signature: string;
}

function fieldsToJson(payload: ReceiptPayload): ReceiptFieldsJson {
  return {
    iss: payload.iss,
    ins: payload.ins,
    iat: payload.iat,
    nce: toHex(payload.nce),
    req: toHex(payload.req),
    res: toHex(payload.res),
    mdl: payload.mdl,
    wts: toHex(payload.wts),
    meas: { tee: payload.meas.tee, m: toHex(payload.meas.m) },
    att: { d: toHex(payload.att.d), ts: payload.att.ts, url: payload.att.url },
    epk: payload.epk,
    tok: { p: payload.tok.p, c: payload.tok.c },
  };
}

function markingToJson(mk: Marking): { sch: string; d: string } {
  return { sch: mk.sch, d: toHex(mk.d) };
}

function stampDisclosureToJson(sd: StampDisclosure): StampDisclosureJson {
  // `uncertaintySeconds` carries `null` as a value and this keeps it a value: a projection that
  // dropped the member for the unmeasured reading would turn "nobody measured" into whichever of
  // "no bound" and "zero" a reader of the JSON happened to prefer.
  return { name: sd.name, unc: sd.uncertaintySeconds };
}

function collateralSlotToJson(slot: CollateralSlot): CollateralSlotJson {
  return slot.presence === 'held' ? { p: slot.presence, d: toHex(slot.sha256) } : { p: slot.presence, r: slot.reason };
}

function itemStampToJson(one: ItemStamp): { t: number; d: string } {
  return { t: one.t, d: toHex(one.d) };
}

/** The `enc` map of a payload: the label, and the key spelled as the hex the wire carries it in. */
function encryptionToJson(enc: Encryption): EncryptionJson {
  return enc.sch === 'none' ? { sch: enc.sch } : { sch: enc.sch, pk: toHex(enc.pk) };
}

export function receiptToJson(payload: ReceiptPayload, signature: Uint8Array, kid: Uint8Array): ReceiptJson {
  const protectedHeader = { alg: 'EdDSA', kid: toHex(kid), typ: 'ashaveri/receipt' };
  // The members both versions state are spelled out here rather than shared with the version that adds one,
  // because a projection whose keys arrived in another order would be a different document to anything that
  // compares these bytes, and a projection that dropped `mk`, `sd`, `cva` or `itm` would hand a reader of
  // the JSON a receipt with nothing to show what it attests. The version decides only whether `enc` is among
  // them, and it is reached through a payload the reader named a version for, so no document gains a member
  // at a number that does not define one.
  //
  // The refusal below is the other half, and it stays the whole of the branching over which versions exist:
  // `parsePayload` answers a number this format does not read before it hands this file a payload, and
  // `assertEncodable` answers it for a payload a caller built by hand, so a projection that fell through to
  // a default shape instead would write one version's members under another number, which is where the
  // cascade this replaced used to end. No document read from bytes arrives here naming another number; the
  // caller with a route past that is the one holding a payload of its own making, and it is answered with the
  // same code the reader and the writer use.
  if (!isReceiptVersion(payload.v)) {
    throw new ReceiptError(
      'UNSUPPORTED_VERSION',
      'a payload naming a version this projection has no members for is not projected as another version',
    );
  }
  const stated = {
    ...fieldsToJson(payload),
    mk: markingToJson(payload.mk),
    sd: stampDisclosureToJson(payload.sd),
    cva: {
      col: collateralSlotToJson(payload.cva.collateral),
      val: collateralSlotToJson(payload.cva.validity),
    },
    itm: payload.itm.map(itemStampToJson),
  };
  const projected: ReceiptPayloadJson = payload.v === 2
    ? { v: 2, ...stated, enc: encryptionToJson(payload.enc) }
    : { v: 1, ...stated };
  return { protectedHeader, payload: projected, signature: toHex(signature) };
}

export function receiptBytesToJson(bytes: Uint8Array): ReceiptJson {
  const decoded = decodeReceipt(bytes);
  return receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
}

export { toHex };
