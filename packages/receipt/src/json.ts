import { ReceiptError } from './errors.js';
import type { CollateralSlot, StampDisclosure } from './disclosure.js';
import { isReceiptVersion } from './receipt.js';
import type { ItemStamp, Marking, ReceiptPayload } from './receipt.js';
import { decodeReceipt } from './receipt.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The twelve fields every payload carries, in the projection this file defines. `v` sits beside them in
 * the one shape below, because the version is what tells a reader which format these bytes were signed
 * under, and this build states one.
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

/** The disclosure of one stamped instant, with its `null` kept as `null` rather than dropped. */
interface StampDisclosureJson {
  name: string;
  unc: number | null;
}

/** The one payload this projection writes: the twelve shared fields, then the mark, the disclosure, the anchor and the items. */
export interface ReceiptPayloadJson extends ReceiptFieldsJson {
  v: 1;
  mk: { sch: string; d: string };
  sd: StampDisclosureJson;
  cva: { col: CollateralSlotJson; val: CollateralSlotJson };
  itm: Array<{ t: number; d: string }>;
}

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

export function receiptToJson(payload: ReceiptPayload, signature: Uint8Array, kid: Uint8Array): ReceiptJson {
  const protectedHeader = { alg: 'EdDSA', kid: toHex(kid), typ: 'ashaveri/receipt' };
  // One shape, spelling all seventeen members out rather than sharing one object built in two places,
  // because a projection whose keys arrived in another order would be a different document to anything
  // that compares these bytes, and a projection that dropped `mk`, `sd`, `cva` or `itm` would hand a
  // reader of the JSON a receipt with nothing to show what it attests. The arms retired with the versions
  // they belonged to: `parsePayload` answers a number this format does not read before it hands this file
  // a payload, and `assertEncodable` answers it for a payload a caller built by hand, so a projection with
  // a branch per number would be a second place a retired version gets a route through.
  // The version is asked first, in the one form the question has now that the arms are gone: not which
  // of several shapes to write, but whether this payload names a version this build has members for at
  // all. No document read from bytes arrives here naming another number, because `parsePayload` answers
  // it upstream; the caller with a route past that is the one holding a payload of its own making, and it
  // is answered with the same code the reader and the writer use rather than with a projection of a
  // version these members do not state.
  if (!isReceiptVersion(payload.v)) {
    throw new ReceiptError(
      'UNSUPPORTED_VERSION',
      'a payload naming a version this projection has no members for is not projected as another version',
    );
  }
  return {
    protectedHeader,
    payload: {
      v: payload.v,
      ...fieldsToJson(payload),
      mk: markingToJson(payload.mk),
      sd: stampDisclosureToJson(payload.sd),
      cva: {
        col: collateralSlotToJson(payload.cva.collateral),
        val: collateralSlotToJson(payload.cva.validity),
      },
      itm: payload.itm.map(itemStampToJson),
    },
    signature: toHex(signature),
  };
}

export function receiptBytesToJson(bytes: Uint8Array): ReceiptJson {
  const decoded = decodeReceipt(bytes);
  return receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
}

export { toHex };
