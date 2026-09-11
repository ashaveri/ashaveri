import { fail } from './errors.js';
import type { TdxQuote } from './types.js';

const MIN_QUOTE_LENGTH = 0x278;

export function parseTdxQuote(quote: Uint8Array): TdxQuote {
  if (quote.length < MIN_QUOTE_LENGTH) {
    fail('MALFORMED_QUOTE', `quote is ${quote.length} bytes, need at least ${MIN_QUOTE_LENGTH}`);
  }
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const section = (offset: number, length: number) => quote.slice(offset, offset + length);
  return {
    raw: quote,
    version: view.getUint16(0x00, true),
    attestationKeyType: view.getUint16(0x02, true),
    teeType: view.getUint32(0x04, true),
    mrTd: section(0xb8, 48),
    mrConfigId: section(0xe8, 48),
    mrOwner: section(0x118, 48),
    mrOwnerConfig: section(0x148, 48),
    rtmr: [section(0x178, 48), section(0x1a8, 48), section(0x1d8, 48), section(0x208, 48)],
    reportData: section(0x238, 64),
  };
}

export function isZero(bytes: Uint8Array): boolean {
  for (const b of bytes) {
    if (b !== 0) return false;
  }
  return true;
}
