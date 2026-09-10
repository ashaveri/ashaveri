import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as nodeSign, constants, type KeyObject } from 'node:crypto';
import { parseCertificateChain } from '../src/index.js';
import { verifyRsaPssSha384 } from '../src/rsa-pss.js';
import { fixture } from './helpers.js';

// Cross-checks the pure-TS RSASSA-PSS verifier against OpenSSL (via Node's
// crypto) at several key sizes and salt lengths.
describe('RSASSA-PSS SHA-384 verification', () => {
  const message = new TextEncoder().encode('the report is the message');

  function rsaKey(modulusLength: number): { modulus: bigint; exponent: bigint; privateKey: KeyObject } {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    return {
      modulus: bigintFromBase64url(jwk.n as string),
      exponent: bigintFromBase64url(jwk.e as string),
      privateKey,
    };
  }

  for (const modulusLength of [2048, 3072, 4096]) {
    it(`verifies an OpenSSL ${modulusLength}-bit PSS signature with a 48-byte salt`, () => {
      const key = rsaKey(modulusLength);
      const signature = new Uint8Array(
        nodeSign('sha384', message, {
          key: key.privateKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 48,
        }),
      );
      expect(verifyRsaPssSha384(message, signature, key.modulus, key.exponent, 48)).toBe(true);
    });
  }

  it('rejects a tampered message', () => {
    const key = rsaKey(2048);
    const signature = new Uint8Array(
      nodeSign('sha384', message, {
        key: key.privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 48,
      }),
    );
    const other = new Uint8Array(message);
    other[0]! ^= 0x01;
    expect(verifyRsaPssSha384(other, signature, key.modulus, key.exponent, 48)).toBe(false);
  });

  it('rejects a tampered signature', () => {
    const key = rsaKey(2048);
    const signature = new Uint8Array(
      nodeSign('sha384', message, {
        key: key.privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 48,
      }),
    );
    signature[10]! ^= 0x01;
    expect(verifyRsaPssSha384(message, signature, key.modulus, key.exponent, 48)).toBe(false);
  });

  it('rejects a signature made with a different salt length', () => {
    const key = rsaKey(2048);
    const signature = new Uint8Array(
      nodeSign('sha384', message, {
        key: key.privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      }),
    );
    expect(verifyRsaPssSha384(message, signature, key.modulus, key.exponent, 48)).toBe(false);
  });

  it('rejects a signature of the wrong byte length', () => {
    const key = rsaKey(2048);
    const signature = new Uint8Array(
      nodeSign('sha384', message, {
        key: key.privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 48,
      }),
    );
    expect(verifyRsaPssSha384(message, signature.subarray(0, signature.length - 1), key.modulus, key.exponent, 48)).toBe(false);
  });

  it('verifies the real ARK self-signature', () => {
    const ark = parseCertificateChain(fixture('amd-ark-milan.pem'))[0]!;
    if (ark.publicKey.kind !== 'rsa') {
      throw new Error('expected RSA ARK');
    }
    expect(ark.signatureAlgorithm.kind).toBe('rsa-pss');
    expect(verifyRsaPssSha384(ark.tbs, ark.signature, ark.publicKey.modulus, ark.publicKey.exponent, 48)).toBe(true);
    const tamperedTbs = new Uint8Array(ark.tbs);
    tamperedTbs[20]! ^= 0x01;
    expect(verifyRsaPssSha384(tamperedTbs, ark.signature, ark.publicKey.modulus, ark.publicKey.exponent, 48)).toBe(false);
  });
});

function bigintFromBase64url(value: string): bigint {
  const hex = Buffer.from(value, 'base64url').toString('hex');
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}
