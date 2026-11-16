import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DUTY_LABEL_REGISTRY_REVISION,
  ReceiptError,
  decodePack,
  encodePackManifest,
  encodePackProtectedHeader,
  issueReceipt,
  packRecordDigest,
  packSigStructure,
  sealPack,
  signingKeyFromSeed,
  verifyPack,
  type PackItem,
  type PackManifest,
  type ReceiptPayload,
  type SigningKey,
} from '../src/index.js';

/**
 * The duty-label registry weighed on the real reader path, through the published pieces and `decodePack`.
 *
 * A pack is assembled from `encodePackManifest`, `encodePackProtectedHeader`, `packSigStructure` and
 * `sealPack`, the four pieces the writer publishes, and handed to `decodePack` and `verifyPack`. Nothing here
 * restates the reader: the bytes are made by the writer and the answer is the reader's own. The two refusals
 * the registry adds are asked of documents that are well-formed in every other respect, so a green answer
 * cannot be the layout refusing a mis-typed member instead of the registry refusing a label.
 *
 * The clock is the registry revision itself, so the assembly instant is after the revision the duty names
 * and `rev` never postdates the reads. The honest and foreign-label packs are acceptances; the unknown label
 * and the revision the entry does not demand are refusals, each under its own named code.
 */

const KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(41));
const BASE = DUTY_LABEL_REGISTRY_REVISION;
const SPAN_FROM = BASE - 60;
const SPAN_TO = BASE + 3;

function receiptPayload(iat: number, nonce: number): ReceiptPayload {
  const digest = sha256(new Uint8Array([nonce]));
  return {
    v: 1,
    iss: 'ashaveri-duty-registry',
    ins: 'cvm-duty-1',
    iat,
    nce: new Uint8Array(16).fill(nonce),
    req: digest,
    res: digest,
    mdl: 'mock-model-1',
    wts: digest,
    meas: { tee: 'software', m: digest },
    att: { d: digest, ts: iat - 60, url: 'https://inference.ashaveri.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
    mk: { sch: 'none', d: sha256(new Uint8Array(0)) },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'this test took no collateral in' },
      validity: { presence: 'not-taken-in', reason: 'this test recorded no validity context' },
    },
    itm: [{ t: iat, d: digest }],
  };
}

function chained(): { items: PackItem[]; anchor: Uint8Array; head: Uint8Array } {
  const anchor = new Uint8Array(32);
  const items: PackItem[] = [];
  let prev: Uint8Array = anchor;
  for (let index = 0; index < 3; index += 1) {
    const iat = BASE + index;
    const item: PackItem = {
      id: `receipt-${String(index)}`,
      iat,
      prov: 'fixture',
      prev,
      receipt: issueReceipt(receiptPayload(iat, index + 1), KEY),
    };
    items.push(item);
    prev = packRecordDigest(item);
  }
  return { items, anchor, head: prev };
}

function manifestOver(duty: PackManifest['duty']): PackManifest {
  const run = chained();
  return {
    v: 1,
    at: SPAN_TO,
    prov: 'fixture',
    span: { from: SPAN_FROM, to: SPAN_TO },
    chain: { anchor: run.anchor, head: run.head },
    duty,
    items: run.items,
    custody: [],
    attached: [],
  };
}

function sealedFromPieces(manifest: PackManifest): Uint8Array {
  const payloadBytes = encodePackManifest(manifest);
  const header = encodePackProtectedHeader(KEY.kid);
  return sealPack(header, payloadBytes, ed25519.sign(packSigStructure(header, payloadBytes), KEY.privateKey));
}

function codeOf(run: () => unknown): string {
  try {
    run();
    return 'accepted';
  } catch (err) {
    return err instanceof ReceiptError ? err.code : `UNCODED:${String(err)}`;
  }
}

const HONEST_DUTY = { art: '19(1)', rev: DUTY_LABEL_REGISTRY_REVISION, required: 3_600, held: SPAN_TO - BASE };

describe('the pack reader weighs the duty-label registry', () => {
  it('verifies a pack under a registry label end to end', () => {
    const bytes = sealedFromPieces(manifestOver(HONEST_DUTY));
    expect(codeOf(() => decodePack(bytes))).toBe('accepted');
    const verified = verifyPack(bytes, { publicKey: KEY.publicKey });
    expect(verified.manifest.duty.art).toBe('19(1)');
    expect(verified.manifest.duty.rev).toBe(DUTY_LABEL_REGISTRY_REVISION);
  });

  it('verifies a pack under a foreign label the retention enum does not carry', () => {
    const bytes = sealedFromPieces(manifestOver({ ...HONEST_DUTY, art: '5(1)(e)' }));
    expect(codeOf(() => decodePack(bytes))).toBe('accepted');
    const verified = verifyPack(bytes, { publicKey: KEY.publicKey });
    expect(verified.manifest.duty.art).toBe('5(1)(e)');
  });

  it('refuses an unknown label with a named code', () => {
    const bytes = sealedFromPieces(manifestOver({ ...HONEST_DUTY, art: '12(1)' }));
    expect(codeOf(() => decodePack(bytes))).toBe('PACK_DUTY_UNKNOWN_LABEL');
    expect(codeOf(() => verifyPack(bytes, { publicKey: KEY.publicKey }))).toBe('PACK_DUTY_UNKNOWN_LABEL');
  });

  it('refuses a known label whose rev does not name the revision the entry demands', () => {
    const bytes = sealedFromPieces(manifestOver({ ...HONEST_DUTY, rev: DUTY_LABEL_REGISTRY_REVISION - 1 }));
    expect(codeOf(() => decodePack(bytes))).toBe('PACK_DUTY_REVISION_UNMAPPED');
    expect(codeOf(() => verifyPack(bytes, { publicKey: KEY.publicKey }))).toBe('PACK_DUTY_REVISION_UNMAPPED');
  });

  it('still refuses a revision after the reads as a contradiction of the document', () => {
    const bytes = sealedFromPieces(manifestOver({ ...HONEST_DUTY, rev: SPAN_TO + 1 }));
    expect(codeOf(() => decodePack(bytes))).toBe('PACK_BAD_MANIFEST');
  });
});