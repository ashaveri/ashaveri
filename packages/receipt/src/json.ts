import type { CollateralSlot, StampDisclosure } from './disclosure.js';
import { ReceiptError } from './errors.js';
import type { ItemStamp, Marking, ReceiptPayload } from './receipt.js';
import { decodeReceipt } from './receipt.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The twelve fields every payload version shares, in the projection this file defines. `v` sits
 * outside it in each variant, because the version is what tells a reader which of the shapes
 * below the rest of the object has.
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

interface ReceiptJsonV1Payload extends ReceiptFieldsJson {
  v: 1;
}

interface ReceiptJsonV2Payload extends ReceiptFieldsJson {
  v: 2;
  mk: { sch: string; d: string };
}

/** The two arms of one anchor slot, spelled as the format spells them: a label, then a digest or a reason. */
type CollateralSlotJson = { p: 'held'; d: string } | { p: 'absent-at-source' | 'not-taken-in'; r: string };

/** The disclosure of one stamped instant, with its `null` kept as `null` rather than dropped. */
interface StampDisclosureJson {
  name: string;
  unc: number | null;
}

interface ReceiptJsonV3Payload extends ReceiptFieldsJson {
  v: 3;
  mk: { sch: string; d: string };
  sd: StampDisclosureJson;
  cva: { col: CollateralSlotJson; val: CollateralSlotJson };
  itm: Array<{ t: number; d: string }>;
}

export type ReceiptPayloadJson = ReceiptJsonV1Payload | ReceiptJsonV2Payload | ReceiptJsonV3Payload;

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
  // The arms spell the envelope out rather than sharing one object, because a projection whose keys
  // arrived in another order would be a different document to anything that compares these bytes. A
  // projection that dropped `mk` would be worse: a v2 receipt with nothing to show what it attests,
  // which is the misreading the version exists to prevent, and the same for the three members a v3
  // receipt was given a version to carry.
  //
  // The switch is exhaustive on the version a payload names, and it replaced a cascade whose last arm
  // was the v1 shape with no condition in front of it. That tail was where a version this file has no
  // arm for landed: a fourth payload would have come out as a version 1 JSON document, its `mk`, `sd`,
  // `cva` and `itm` dropped and its `v` rewritten to a number it does not name, and no type check
  // would have said so, because every shape of the union satisfies the v1 arm's object literal. An
  // unlisted version now reaches the default, where the only type the payload can be bound to is
  // `never`, so widening the union without adding an arm here stops being a projection and is a
  // compile error at the file that has to answer for it.
  switch (payload.v) {
    case 3:
      return {
        protectedHeader,
        payload: {
          v: 3,
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
    case 2:
      return {
        protectedHeader,
        payload: { v: 2, ...fieldsToJson(payload), mk: markingToJson(payload.mk) },
        signature: toHex(signature),
      };
    case 1:
      return { protectedHeader, payload: { v: 1, ...fieldsToJson(payload) }, signature: toHex(signature) };
    default: {
      // Bound and deliberately unread. Every version the union names has an arm above, so this arm
      // compiles today and it is the assignment that fails the day a member reaches it without one: an
      // arm that never compiled would guard nothing, and one that compiled whatever the union held would
      // be the cascade this replaced. The refusal is for the caller that hands this function a payload
      // naming a version of its own making, because no document read from bytes arrives here:
      // `decodeReceipt` answers an unreadable version before there is a payload to project. It projects
      // nothing rather than guessing a version whose members these are not.
      const _exhaustive: never = payload;
      throw new ReceiptError(
        'UNSUPPORTED_VERSION',
        'a payload naming a version this projection has no arm for is not projected as another version',
      );
    }
  }
}

export function receiptBytesToJson(bytes: Uint8Array): ReceiptJson {
  const decoded = decodeReceipt(bytes);
  return receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
}

export { toHex };
