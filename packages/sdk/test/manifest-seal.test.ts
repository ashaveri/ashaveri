import { describe, expect, it } from 'vitest';
import {
  DEPLOYMENT_MANIFEST_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodeCoseSign1,
  decodeSealedDeploymentManifest,
  encodeCanonical,
  isSealedDeploymentManifest,
  sealDeploymentManifest,
  signCoseSign1,
  toHex,
  verifySealedDeploymentManifest,
} from '@ashaveri/receipt';
import { MANIFEST_KEY, RECEIPT_KEY, STRANGER_KEY, plainManifest, sealedManifest } from './manifest-documents.js';

/**
 * The signed deployment manifest at the boundary the SDK stands on.
 *
 * Two things are under test here and they are different things. One is whether the envelope is what
 * `manifest.cddl` says: four elements, tag 18, a protected header carrying the three labels the receipt
 * signs with and nothing else, and a payload that is the served JSON byte for byte. The other is
 * whether a reader can tell this document apart from the two other things one deployment signs, which
 * is the whole of the content type's job, and which is tested by handing each reader the other's bytes.
 *
 * The header layout is held against the receipt's own builder rather than against a list written in
 * this file: `signCoseSign1` is what `issueReceipt` calls, so comparing a manifest's protected header
 * with what that function writes says the two envelopes are the same container with one field moved,
 * and says it without this suite being able to move both sides at once.
 */

function failure(fn: () => unknown): { readonly code: string; readonly message: string } {
  try {
    fn();
  } catch (err) {
    if (err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw err;
  }
  throw new Error('the reader accepted bytes this case expects it to refuse');
}

function indexOf(bytes: Uint8Array, needle: Uint8Array): number {
  const start = Buffer.from(bytes).indexOf(Buffer.from(needle));
  if (start < 0) throw new Error('the text this case tampers with is not in the envelope');
  return start;
}

/**
 * One character of the document inside a finished seal, moved. The replacement is the same length, so
 * the CBOR around it stays whole and the only thing a reader can find is a signature that no longer
 * covers what it is reading, which is the state this format has to refuse rather than downgrade.
 */
function tampered(bytes: Uint8Array): Uint8Array {
  const out = bytes.slice();
  const at = indexOf(out, new TextEncoder().encode('dpl-manifestseal'));
  out[at + 15] = 0x78;
  return out;
}

function headerOf(protectedBytes: Uint8Array): Map<unknown, unknown> {
  const decoded = decodeCanonical(protectedBytes);
  if (!(decoded instanceof Map)) throw new Error('a protected header did not decode as a map');
  return decoded;
}

describe('the sealed deployment manifest envelope', () => {
  it('signs the bytes it was handed and returns exactly those bytes', () => {
    const document = plainManifest();
    const seal = verifySealedDeploymentManifest(sealDeploymentManifest(document, MANIFEST_KEY), MANIFEST_KEY.publicKey);
    expect(toHex(seal.payloadBytes)).toBe(toHex(document));
    expect(seal.header).toEqual({
      alg: -8,
      kid: MANIFEST_KEY.kid,
      contentType: DEPLOYMENT_MANIFEST_CONTENT_TYPE,
    });
  });

  it('declares the header the receipt builder declares, with one field moved', () => {
    const document = plainManifest();
    const fromTheReceiptBuilder = decodeCoseSign1(signCoseSign1(document, MANIFEST_KEY));
    const fromThisFormat = decodeSealedDeploymentManifest(sealDeploymentManifest(document, MANIFEST_KEY));
    const receiptHeader = headerOf(fromTheReceiptBuilder.protectedBytes);
    const manifestHeader = headerOf(fromThisFormat.protectedBytes);

    // Same three labels, same algorithm, same key id: one deployment writes all its documents this way.
    expect([...manifestHeader.keys()].sort((a, b) => Number(a) - Number(b))).toEqual([1, 3, 4]);
    expect(manifestHeader.get(1)).toBe(receiptHeader.get(1));
    expect(toHex(manifestHeader.get(4) as Uint8Array)).toBe(toHex(receiptHeader.get(4) as Uint8Array));
    // And the one field that separates the two documents, which is the only thing that does.
    expect(receiptHeader.get(3)).toBe(RECEIPT_CONTENT_TYPE);
    expect(manifestHeader.get(3)).toBe(DEPLOYMENT_MANIFEST_CONTENT_TYPE);
  });

  it('refuses a receipt handed to the manifest reader and a manifest handed to the receipt reader', () => {
    const document = plainManifest();
    const asReceipt = signCoseSign1(document, MANIFEST_KEY);
    const asManifest = sealDeploymentManifest(document, MANIFEST_KEY);
    // Both are valid `COSE_Sign1` structures over the same payload and the same key, and both verify
    // under that key. Only the content type says which claim a reader is holding, so each reader has to
    // stop the other's document before it consults a key, and the message has to name what it saw.
    const receiptAtTheManifestRoute = failure(() => decodeSealedDeploymentManifest(asReceipt));
    expect(receiptAtTheManifestRoute.code).toBe('BAD_PROTECTED_HEADER');
    expect(receiptAtTheManifestRoute.message).toContain(`typ=${RECEIPT_CONTENT_TYPE}`);
    const manifestAtTheReceiptRoute = failure(() => decodeCoseSign1(asManifest));
    expect(manifestAtTheReceiptRoute.code).toBe('BAD_PROTECTED_HEADER');
    expect(manifestAtTheReceiptRoute.message).toContain(`typ=${DEPLOYMENT_MANIFEST_CONTENT_TYPE}`);
  });

  it('refuses a body that changed under a signature that still looks valid', () => {
    const sealed = sealedManifest();
    const moved = tampered(sealed);
    // The decode still succeeds: the envelope is whole, the header is the right one, and the signature
    // is sixty-four bytes. The refusal is the verification's, and it is the only honest answer about a
    // document somebody edited after it was signed.
    expect(decodeSealedDeploymentManifest(moved).header.contentType).toBe(DEPLOYMENT_MANIFEST_CONTENT_TYPE);
    expect(failure(() => verifySealedDeploymentManifest(moved, MANIFEST_KEY.publicKey)).code).toBe(
      'INVALID_SIGNATURE',
    );
  });

  it('refuses to credit a seal to a key that did not make it', () => {
    const sealed = sealedManifest();
    expect(failure(() => verifySealedDeploymentManifest(sealed, STRANGER_KEY.publicKey)).code).toBe('KID_MISMATCH');
    expect(failure(() => verifySealedDeploymentManifest(sealed, RECEIPT_KEY.publicKey)).code).toBe('KID_MISMATCH');
  });

  it('puts the external AAD where the receipt puts it, and nowhere else', () => {
    const aad = new TextEncoder().encode('manifest-seal-external-aad');
    const sealed = sealDeploymentManifest(plainManifest(), MANIFEST_KEY, aad);
    expect(verifySealedDeploymentManifest(sealed, MANIFEST_KEY.publicKey, aad).header.kid).toEqual(MANIFEST_KEY.kid);
    // Left out, or replaced by the same length of nothing: either way the bytes under the signature are
    // other than the ones that went into it, and an AAD is worth having only if that is a refusal.
    expect(failure(() => verifySealedDeploymentManifest(sealed, MANIFEST_KEY.publicKey)).code).toBe(
      'INVALID_SIGNATURE',
    );
    expect(
      failure(() => verifySealedDeploymentManifest(sealed, MANIFEST_KEY.publicKey, new Uint8Array(aad.length))).code,
    ).toBe('INVALID_SIGNATURE');
  });

  it('decides which of the two shapes it was handed from the first byte, not from a header', () => {
    expect(isSealedDeploymentManifest(plainManifest())).toBe(false);
    expect(isSealedDeploymentManifest(sealedManifest())).toBe(true);
    expect(isSealedDeploymentManifest(new Uint8Array(0))).toBe(false);
    // A whitespace-prefixed JSON document is still JSON to `JSON.parse` and still refused here, which
    // is the safe direction: it reaches a parser that reports it rather than a signature check that
    // would have nothing to verify.
    expect(isSealedDeploymentManifest(new TextEncoder().encode('  {"v":1}'))).toBe(false);
  });

  it('refuses the bytes that only start like a seal', () => {
    const sealed = sealedManifest();
    // A canonical CBOR array is a whole document that is not this one, and the tag is the first thing
    // a reader can ask about it.
    expect(failure(() => decodeSealedDeploymentManifest(encodeCanonical([1, 2, 3]))).code).toBe('NOT_COSE_SIGN1');
    // The rest fail further down than the tag: a lone tag byte, a JSON document, and a seal missing the
    // tail of its signature are each refused while the bytes are still being read, so the code names
    // the decode rather than the structure. A reader that called that a manifest of the wrong shape
    // would be reporting a truncation as a confusion.
    expect(failure(() => decodeSealedDeploymentManifest(new Uint8Array([0xd2]))).code).toBe('MALFORMED_CBOR');
    expect(failure(() => decodeSealedDeploymentManifest(plainManifest())).code).toBe('MALFORMED_CBOR');
    expect(failure(() => decodeSealedDeploymentManifest(sealed.slice(0, sealed.length - 8))).code).toBe(
      'MALFORMED_CBOR',
    );
  });

  it('refuses a signing key that is not the shape this format signs with', () => {
    const short = { ...MANIFEST_KEY, kid: new Uint8Array(31) };
    expect(failure(() => sealDeploymentManifest(plainManifest(), short)).code).toBe('BAD_SIGNING_KEY');
    const borrowedKid = { ...MANIFEST_KEY, kid: RECEIPT_KEY.kid };
    expect(failure(() => sealDeploymentManifest(plainManifest(), borrowedKid)).code).toBe('BAD_SIGNING_KEY');
    // A seed of the wrong width is the same refusal from the other side of the pair.
    const shortPrivate = { ...MANIFEST_KEY, privateKey: new Uint8Array(16) };
    expect(failure(() => sealDeploymentManifest(plainManifest(), shortPrivate)).code).toBe('BAD_SIGNING_KEY');
  });
});
