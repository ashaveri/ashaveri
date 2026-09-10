import type { ReceiptPayload } from './receipt.js';
import { decodeReceipt } from './receipt.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export interface ReceiptJson {
  protectedHeader: { alg: string; kid: string; typ: string };
  payload: {
    v: number;
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
  };
  signature: string;
}

export function receiptToJson(payload: ReceiptPayload, signature: Uint8Array, kid: Uint8Array): ReceiptJson {
  return {
    protectedHeader: { alg: 'EdDSA', kid: toHex(kid), typ: 'ashaveri/receipt' },
    payload: {
      v: payload.v,
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
    },
    signature: toHex(signature),
  };
}

export function receiptBytesToJson(bytes: Uint8Array): ReceiptJson {
  const decoded = decodeReceipt(bytes);
  return receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
}

export { toHex };
