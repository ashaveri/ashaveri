import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  decodeReceipt,
  hashRequest,
  issueReceipt,
  signingKeyFromSeed,
  type Marking,
  type ReceiptPayload,
} from '@ashaveri/receipt';

/**
 * A receipt over the response bytes the published marked vector attests, signed under the key the
 * fixtures publish their receipts under.
 *
 * The seventeen fields are lifted out of the published `receipt-marked-v1` document rather than spelled
 * out beside it, so the only differences between the two are the ones a case names for itself: the
 * marking claim, and the anchor a held-slot case needs material beside its digest. Every pin, digest, kid
 * and stamp the fixture policy and deployment manifest already accept still holds.
 *
 * Shared by `verify-receipt` and `verify-handover` because the two report on the same document, and a
 * second builder in the second file would be two spellings of one receipt free to disagree.
 */

const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

/** The receipt signing key the fixtures are issued under, seed and all, as its own file publishes it. */
const RECEIPT_SEED = (
  JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as { privateKey: string }
).privateKey;

/** The published marked receipt, decoded: the document the cases below differ from only by a member. */
const published = decodeReceipt(new Uint8Array(readFileSync(`${DATA}receipts/receipt-marked-v1.cbor`))).payload;
if (published.v !== 1) {
  throw new Error(`the published marked vector is not a v1 document but a v${published.v} one`);
}

/** The marking the published vector attests, which is the one its response bytes carry. */
export const ATTESTED_MARKING: Marking = published.mk;

/** A digest that is not the attested region, for the case that has to hand the verifier a false claim. */
export function wrongMarking(): Marking {
  return { sch: ATTESTED_MARKING.sch, d: hashRequest(new TextEncoder().encode('a region these bytes do not carry')) };
}

/** A receipt over the published vector's response, attesting `mk`, signed under the fixture key. */
export function stampedReceiptBytes(mk: Marking): Uint8Array {
  const payload: ReceiptPayload = {
    ...published,
    mk,
    cva: {
      collateral: { presence: 'held', sha256: hashRequest(new TextEncoder().encode('the collateral the appraisal ran on')) },
      validity: { presence: 'not-taken-in', reason: 'the collector read no window' },
    },
    itm: [{ t: published.iat, d: hashRequest(new TextEncoder().encode('the first item of the response')) }],
  };
  return issueReceipt(payload, signingKeyFromSeed(new Uint8Array(Buffer.from(RECEIPT_SEED, 'hex'))));
}
