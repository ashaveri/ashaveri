import type { Marking, ReceiptPayload } from './receipt.js';
import { decodeReceipt } from './receipt.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The twelve fields both payload versions share, in the projection this file defines. `v` sits
 * outside it in each variant, because the version is what tells a reader which of the two shapes
 * the rest of the object has.
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

export type ReceiptPayloadJson = ReceiptJsonV1Payload | ReceiptJsonV2Payload;

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

export function receiptToJson(payload: ReceiptPayload, signature: Uint8Array, kid: Uint8Array): ReceiptJson {
  const protectedHeader = { alg: 'EdDSA', kid: toHex(kid), typ: 'ashaveri/receipt' };
  // The two branches spell the envelope out rather than sharing one object, because a projection
  // whose keys arrived in another order would be a different document to anything that compares
  // these bytes. A projection that dropped `mk` would be worse: a v2 receipt with nothing to show
  // what it attests, which is the misreading the version exists to prevent.
  if (payload.v === 2) {
    return {
      protectedHeader,
      payload: { v: 2, ...fieldsToJson(payload), mk: markingToJson(payload.mk) },
      signature: toHex(signature),
    };
  }
  return { protectedHeader, payload: { v: 1, ...fieldsToJson(payload) }, signature: toHex(signature) };
}

export function receiptBytesToJson(bytes: Uint8Array): ReceiptJson {
  const decoded = decodeReceipt(bytes);
  return receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
}

export { toHex };
