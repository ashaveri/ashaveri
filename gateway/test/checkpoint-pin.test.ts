import { describe, expect, it } from 'vitest';
import {
  canonicalDigest,
  generatePinKeyPair,
  signHeadPin,
  verifyHeadPin,
  HeadPinError,
  type HeadPin,
} from '../src/checkpoint-pin.js';

/**
 * The independence rule a head pin is worth nothing without.
 *
 * The first two cases are the pair the whole module exists for: a pin signed by a key that is not one of
 * the issuance identities is accepted, and a pin signed by a key that is one of them is refused. The
 * refused pin carries a signature that verifies, asserted directly below rather than left to inference,
 * because a refusal that only looks right against a broken signature proves nothing about the rule.
 */

const SCOPE = canonicalDigest({ subject: 'pin-fixture', intake: { from: 0, to: 3 } });
const HEAD = { sequence: 3, sha256: 'a'.repeat(64) };

const issuance = generatePinKeyPair();
const holder = generatePinKeyPair();

describe('verifyHeadPin', () => {
  it('accepts a pin signed by a key that issued no head', () => {
    const pin = signHeadPin({ key: holder, head: HEAD, scope: SCOPE });
    expect(verifyHeadPin(pin, { issuedBy: [issuance.keyId], scope: SCOPE })).toEqual(HEAD);
  });

  it('refuses a pin signed by the key that issued the head, over a signature that verifies', () => {
    const pin = signHeadPin({ key: issuance, head: HEAD, scope: SCOPE });
    // The same bytes are accepted the moment the identity is not one that issues a head, which is what
    // says the refusal below is the identity rule and not a signature this pin happens to fail.
    expect(verifyHeadPin(pin, { issuedBy: [], scope: SCOPE })).toEqual(HEAD);
    const thrown = (() => {
      try {
        verifyHeadPin(pin, { issuedBy: [issuance.keyId], scope: SCOPE });
        return undefined;
      } catch (error) {
        return error;
      }
    })();
    expect(thrown).toBeInstanceOf(HeadPinError);
    expect((thrown as HeadPinError).code).toBe('PIN_SELF_ISSUED');
    expect((thrown as HeadPinError).message).toContain(issuance.keyId);
  });

  it('refuses a pin whose signer id is not what its own public key digests to', () => {
    const pin = signHeadPin({ key: holder, head: HEAD, scope: SCOPE });
    const lied: HeadPin = { ...pin, signer: { ...pin.signer, keyId: issuance.keyId } };
    expect(() => verifyHeadPin(lied, { issuedBy: [], scope: SCOPE })).toThrow(/PIN_FORM/u);
  });

  it('refuses a pin offered against a scope it was not written over', () => {
    const pin = signHeadPin({ key: holder, head: HEAD, scope: SCOPE });
    const other = canonicalDigest({ subject: 'pin-fixture', intake: { from: 0, to: 4 } });
    expect(() => verifyHeadPin(pin, { issuedBy: [issuance.keyId], scope: other })).toThrow(/PIN_SCOPE_MISMATCH/u);
  });

  it('refuses a pin whose head was moved after it was signed', () => {
    const pin = signHeadPin({ key: holder, head: HEAD, scope: SCOPE });
    const moved: HeadPin = { ...pin, head: { sequence: HEAD.sequence, sha256: 'b'.repeat(64) } };
    expect(() => verifyHeadPin(moved, { issuedBy: [issuance.keyId], scope: SCOPE })).toThrow(/PIN_SIGNATURE_INVALID/u);
  });

  it('names the issuance set as the whole of what turns one accept into the other refusal', () => {
    const pin = signHeadPin({ key: holder, head: HEAD, scope: SCOPE });
    expect(verifyHeadPin(pin, { issuedBy: [], scope: SCOPE })).toEqual(HEAD);
    expect(() => verifyHeadPin(pin, { issuedBy: [issuance.keyId, holder.keyId], scope: SCOPE })).toThrow(/PIN_SELF_ISSUED/u);
  });

  it('folds a scope to one digest whichever order its members arrived in', () => {
    expect(canonicalDigest({ a: 1, b: { c: 2, d: [3, 4] } })).toBe(canonicalDigest({ b: { d: [3, 4], c: 2 }, a: 1 }));
  });
});
