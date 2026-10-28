import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  SMALL_ORDER_ENCODINGS,
  isCanonicalPointEncoding,
  isScalarInGroupOrder,
  isSmallOrderPublicKey,
  nobleStrictVerify,
  preferredStrictVerify,
  refusalBeforeTheEquation,
  runtimeStrictVerify,
  strictVerifySource,
} from '../src/strict-ed25519.js';
import { decodeCoseSign1 } from '../src/cose.js';
import { encodeCanonical } from '../src/cbor.js';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  popSigningString,
  verifyPopSignature,
  type PopFields,
} from '../src/pop.js';

/**
 * The reference throughout is `nobleStrictVerify`, the rule this repository publishes, and the subject is
 * `preferredStrictVerify`, the clauses plus the runtime's own primitive. The two are not the same equation, so
 * the difference is measured and pinned here rather than described: the shipped rule clears the cofactor before
 * comparing, the platform does not, and the seven encodings that turn on the difference are named below.
 */

const DATA = fileURLToPath(new URL('../../fixtures/data', import.meta.url));
const FIELD_PRIME = (1n << 255n) - 19n;
const GROUP_ORDER = ed25519.CURVE.n;
const IDENTITY = ed25519.Point.ZERO;
const IDENTITY_ENCODING = '0100000000000000000000000000000000000000000000000000000000000000';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, 'hex'));
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const encode = (text: string): Uint8Array => new TextEncoder().encode(text);
const toLittleEndian = (value: bigint, length: number): Uint8Array => {
  const out = new Uint8Array(length);
  let rest = value;
  for (let index = 0; index < length; index += 1) {
    out[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};
const fromLittleEndian = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index] ?? 0);
  return value;
};

/** The platform call with nothing in front of it, which is what the clauses above it exist to refuse. */
function nativeAlone(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    const der = Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)]);
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

/** A key and its scalar, so a case can be built on the far side of the discrete log. */
function keyWithKnownScalar(fill: number): { readonly seed: Uint8Array; readonly publicKey: Uint8Array; readonly scalar: bigint } {
  const seed = new Uint8Array(32).fill(fill);
  const digest = sha512(seed);
  digest[0] = (digest[0] ?? 0) & 248;
  digest[31] = ((digest[31] ?? 0) & 127) | 64;
  return { seed, publicKey: ed25519.getPublicKey(seed), scalar: fromLittleEndian(digest.subarray(0, 32)) };
}

const TORSION = SMALL_ORDER_ENCODINGS.map(toHex).sort();

describe('the small-order set the guard refuses', () => {
  it('is the eight encodings the curve derives, not the eight these literals were written against', () => {
    // A point is of order dividing eight when eight times it is the identity. Random points do not have to be,
    // so each is pushed into the torsion subgroup by multiplying by `L - 1` and adding itself, which is `-8R`
    // plus `R`: the cofactor times the point, negated. The identity is the one the construction never yields.
    const found = new Set<string>([toHex(IDENTITY.toBytes())]);
    for (let attempt = 0; attempt < 40_000 && found.size < 8; attempt += 1) {
      const label = encode(`torsion derivation ${String(attempt)}`);
      const bytes = Uint8Array.from(sha512(label).subarray(0, 32));
      bytes[31] = (bytes[31] ?? 0) & 0x7f;
      let point;
      try {
        point = ed25519.Point.fromBytes(bytes, true);
      } catch {
        continue;
      }
      const inTorsion = point.multiply(GROUP_ORDER - 1n).add(point);
      if (inTorsion.multiply(8n).equals(IDENTITY)) found.add(toHex(inTorsion.toBytes()));
    }
    expect(found.size).toBe(8);
    expect([...found].sort()).toEqual(TORSION);
    expect(TORSION).toEqual([...ED25519_TORSION_SUBGROUP].sort());
  });

  it('is refused as a public key, and nothing outside it is', () => {
    for (const encoding of TORSION) {
      const key = fromHex(encoding);
      expect(isSmallOrderPublicKey(key), encoding).toBe(true);
      // A zero signature is inside every range the other clauses check, so the reason this pair is refused is
      // the key alone.
      expect(refusalBeforeTheEquation(new Uint8Array(64), key), encoding).toBe('the public key is a point of small order');
    }
    expect(isSmallOrderPublicKey(keyWithKnownScalar(7).publicKey)).toBe(false);
    expect(isSmallOrderPublicKey(new Uint8Array(31))).toBe(false);
  });
});

describe('each clause is a refusal, and the ones the platform waves through are named', () => {
  const message = encode('clause witness');
  const { seed, publicKey: realKey } = keyWithKnownScalar(11);
  const valid = ed25519.sign(message, seed);

  it('refuses the R = A, S = 0 forgery over a small-order key, which the platform takes for some messages', () => {
    // `[S]B = R + [k]A` with `S = 0` and `R = A` is `[(k + 1)]A = O`, which a point of order two, four or eight
    // satisfies for one message in eight, four or two. So which spellings the platform waves through is a
    // property of the message as much as of the key, and what is pinned here is that the strict rule waves
    // through none of them.
    let admittedByThePlatform = 0;
    for (const encoding of TORSION) {
      const key = fromHex(encoding);
      for (const label of ['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh', 'eighth']) {
        const body = encode(`forgery ${label}`);
        const forgery = new Uint8Array(64);
        forgery.set(key, 0);
        expect(nobleStrictVerify(forgery, body, key), `the shipped rule on ${encoding}`).toBe(false);
        expect(preferredStrictVerify(forgery, body, key), `the guard on ${encoding}`).toBe(false);
        if (nativeAlone(forgery, body, key)) admittedByThePlatform += 1;
      }
    }
    expect(admittedByThePlatform).toBeGreaterThan(0);
    // The identity is the case that needs no luck: every message satisfies it, and both strict readers refuse it.
    const identity = fromHex(IDENTITY_ENCODING);
    const trivial = new Uint8Array(64);
    trivial.set(identity, 0);
    expect(nativeAlone(trivial, message, identity)).toBe(true);
    expect(preferredStrictVerify(trivial, message, identity)).toBe(false);
    expect(nobleStrictVerify(trivial, message, identity)).toBe(false);
  });

  it('refuses a second spelling of the same point, which the platform reads as the key it spells', () => {
    // Only a `y` under nineteen has a second spelling, because the sign bit takes the two-hundred-and-fifty-fifth
    // bit. The identity's is what this case is built on, since the identity accepts a signature without work.
    const identity = fromHex(IDENTITY_ENCODING);
    const secondSpelling = toLittleEndian(FIELD_PRIME + 1n, 32);
    expect(fromLittleEndian(secondSpelling) % FIELD_PRIME).toBe(1n);
    expect(isCanonicalPointEncoding(identity)).toBe(true);
    expect(isCanonicalPointEncoding(secondSpelling)).toBe(false);
    const forgery = new Uint8Array(64);
    forgery.set(identity, 0);
    // The canonical spelling is refused by the torsion clause and this one by the canonical clause: two ways of
    // refusing the same key, which is what makes each of them the reason it exists.
    expect(refusalBeforeTheEquation(forgery, identity)).toBe('the public key is a point of small order');
    expect(refusalBeforeTheEquation(forgery, secondSpelling)).toBe('the public key is not a canonical point encoding');
    expect(nativeAlone(forgery, message, secondSpelling), 'the platform reduces the key modulo the prime').toBe(true);
    expect(preferredStrictVerify(forgery, message, secondSpelling)).toBe(false);
    expect(nobleStrictVerify(forgery, message, secondSpelling)).toBe(false);
  });

  it('refuses the sign bit on the two encodings whose x is zero', () => {
    for (const y of [1n, FIELD_PRIME - 1n]) {
      const unsigned = toLittleEndian(y, 32);
      const signed = toLittleEndian(y | (1n << 255n), 32);
      expect(isCanonicalPointEncoding(unsigned), `y=${String(y)} unsigned`).toBe(true);
      expect(isCanonicalPointEncoding(signed), `y=${String(y)} signed`).toBe(false);
      expect(nobleStrictVerify(valid, message, signed)).toBe(false);
      expect(preferredStrictVerify(valid, message, signed)).toBe(false);
    }
    // And one of them the platform takes on a good day: `y = -1` written as though its zero `x` were negative is
    // the same point as the unsigned spelling, so a signature the platform accepts against one it accepts against
    // the other. Asked rather than asserted, because which of the two the equation happens to satisfy is the
    // message's doing, and the refusal below is what is claimed either way.
    const minusOne = toLittleEndian(FIELD_PRIME - 1n, 32);
    const signedMinusOne = toLittleEndian((FIELD_PRIME - 1n) | (1n << 255n), 32);
    const forgery = new Uint8Array(64);
    forgery.set(minusOne, 0);
    if (nativeAlone(forgery, message, minusOne)) {
      expect(nativeAlone(forgery, message, signedMinusOne), 'the platform ignores the sign of a zero x').toBe(true);
    }
    expect(preferredStrictVerify(forgery, message, signedMinusOne)).toBe(false);
    expect(nobleStrictVerify(forgery, message, signedMinusOne)).toBe(false);
  });

  it('refuses the malleable twin S + L, which is the same group element in a second encoding', () => {
    const realScalar = fromLittleEndian(valid.subarray(32));
    const twin = new Uint8Array([...valid.subarray(0, 32), ...toLittleEndian(realScalar + GROUP_ORDER, 32)]);
    expect(isScalarInGroupOrder(valid.subarray(32))).toBe(true);
    expect(isScalarInGroupOrder(twin.subarray(32))).toBe(false);
    expect(refusalBeforeTheEquation(twin, realKey)).toBe('the scalar is at or past the group order');
    expect(nobleStrictVerify(twin, message, realKey)).toBe(false);
    expect(preferredStrictVerify(twin, message, realKey)).toBe(false);
    // This platform refuses the twin itself, so the clause costs a byte compare and is not what refuses here.
    // It is kept because the rule is stated here in full, and a runtime that reduced the scalar would be
    // refused by it rather than absorbed by it.
    expect(nativeAlone(twin, message, realKey)).toBe(false);
  });

  it('refuses the two widths before anything is read out of the bytes', () => {
    expect(refusalBeforeTheEquation(valid.subarray(0, 63), realKey)).toBe('the signature is not 64 bytes');
    expect(refusalBeforeTheEquation(new Uint8Array(65), realKey)).toBe('the signature is not 64 bytes');
    expect(refusalBeforeTheEquation(valid, realKey.subarray(0, 31))).toBe('the public key is not 32 bytes');
    expect(preferredStrictVerify(valid, message, realKey.subarray(0, 31))).toBe(false);
    expect(refusalBeforeTheEquation(valid, realKey)).toBeNull();
  });
});

describe('the two paths check different equations, and that is measured', () => {
  const message = encode('small-order R');
  const { publicKey, scalar } = keyWithKnownScalar(7);

  /** The signature the holder of this scalar could write with `R` fixed to the encoding given. */
  function signatureWithFixedR(rBytes: Uint8Array): Uint8Array {
    const hash =
      fromLittleEndian(Uint8Array.from(sha512(Buffer.concat([Buffer.from(rBytes), Buffer.from(publicKey), Buffer.from(message)])))) %
      GROUP_ORDER;
    return new Uint8Array([...rBytes, ...toLittleEndian((hash * scalar) % GROUP_ORDER, 32)]);
  }

  it('the shipped rule admits seven small-order R encodings the runtime refuses, and the guard takes the runtime', () => {
    // `[8](R + [k]A - [S]B) = 0` holds for every small-order R once `S` is `k` times the scalar; the exact
    // equation `[S]B = R + [k]A` holds only for the identity. So the platform refuses seven encodings the
    // library admits, and the guard - which is the clauses plus the platform - refuses them too.
    const refusedByTheRuntime: string[] = [];
    const admittedByBoth: string[] = [];
    for (const encoding of TORSION) {
      const signature = signatureWithFixedR(fromHex(encoding));
      const guarded = preferredStrictVerify(signature, message, publicKey);
      expect(nativeAlone(signature, message, publicKey), `the platform on ${encoding}`).toBe(guarded);
      expect(nobleStrictVerify(signature, message, publicKey), `the shipped rule admits ${encoding}`).toBe(true);
      if (guarded) admittedByBoth.push(encoding);
      else refusedByTheRuntime.push(encoding);
    }
    expect(admittedByBoth).toEqual([IDENTITY_ENCODING]);
    expect(refusedByTheRuntime).toHaveLength(7);
  });

  it('refuses none of them by a clause, so it is the equation and not the guard that answers', () => {
    for (const encoding of TORSION) {
      const signature = signatureWithFixedR(fromHex(encoding));
      expect(refusalBeforeTheEquation(signature, publicKey), encoding).toBeNull();
    }
  });

  it('and never refuses a signature a client actually produced', () => {
    // A signer sets `R` to `[r]B`, which is in the prime-order subgroup, and the identity is that subgroup's
    // only small-order point. Sixty-four fresh signatures over the same key, each answering yes twice.
    const { seed, publicKey: key } = keyWithKnownScalar(3);
    for (let round = 0; round < 64; round += 1) {
      const body = encode(`client signature ${String(round)}`);
      const signature = ed25519.sign(body, seed);
      expect(refusalBeforeTheEquation(signature, key), `round ${String(round)}`).toBeNull();
      expect(preferredStrictVerify(signature, body, key)).toBe(true);
      expect(nobleStrictVerify(signature, body, key)).toBe(true);
    }
    expect(key).not.toBe(IDENTITY_ENCODING);
  });
});

describe('the runtime seam', () => {
  const message = encode('seam');
  const { seed, publicKey } = keyWithKnownScalar(5);
  const valid = ed25519.sign(message, seed);

  it('asks the runtime only after every clause has passed, and with the key it was handed', () => {
    const asked: string[] = [];
    const stub = runtimeStrictVerify({
      createPublicKey: (input) => {
        asked.push(toHex(input.key));
        return { role: 'key' };
      },
      verify: (_algorithm, _message, _key, _signature) => true,
    });
    expect(stub).not.toBeNull();
    const verifier = stub!;
    expect(verifier(valid, message, publicKey)).toBe(true);
    expect(asked).toHaveLength(1);
    expect(asked[0]).toBe(`302a300506032b6570032100${toHex(publicKey)}`);
    expect(verifier(new Uint8Array(64), message, fromHex(TORSION[1]!))).toBe(false);
    expect(asked, 'a refusal before the equation never reaches the runtime').toHaveLength(1);
  });

  it('answers a runtime that throws as a refusal, and a runtime that is absent as null', () => {
    const throwing = runtimeStrictVerify({
      createPublicKey: () => {
        throw new Error('the runtime will not build this key');
      },
      verify: () => true,
    });
    expect(throwing).not.toBeNull();
    expect(throwing!(valid, message, publicKey)).toBe(false);
    expect(runtimeStrictVerify(null)).toBeNull();
  });

  it('prefers the runtime here, and says so in the one word the banner prints', () => {
    expect(strictVerifySource).toBe('runtime');
    expect(preferredStrictVerify).not.toBe(nobleStrictVerify);
  });
});

describe('the differential sweep', () => {
  // A deterministic source, so a failure names the case that produced it. `ASHAVERI_SWEEP_CASES` lifts the count
  // for a run that is meant to be large; the default is what a `pnpm test` on a laptop answers in seconds.
  const CASES = Number(process.env.ASHAVERI_SWEEP_CASES ?? '1200');
  let state = 20261028n;
  const nextBytes = (length: number): Uint8Array => {
    const out = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
      out[index] = Number((state >> 33n) & 0xffn);
    }
    return out;
  };
  const nextInt = (bound: number): number => Number(fromLittleEndian(nextBytes(8)) % BigInt(bound));

  /** One case: the bytes, and the class name the tally reports under when two readers part ways. */
  function buildCase(index: number): readonly [string, Uint8Array, Uint8Array, Uint8Array] {
    const message = nextBytes(1 + nextInt(200));
    const seed = nextBytes(32);
    const publicKey = ed25519.getPublicKey(seed);
    const signature = ed25519.sign(message, seed);
    const randomPoint = (): Uint8Array => {
      const bytes = nextBytes(32);
      bytes[31] = (bytes[31] ?? 0) & 0x7f;
      return bytes;
    };
    switch (index % 12) {
      case 0:
        return ['valid', signature, publicKey, message];
      case 1:
        return [
          'malleable twin',
          new Uint8Array([...signature.subarray(0, 32), ...toLittleEndian(fromLittleEndian(signature.subarray(32)) + GROUP_ORDER, 32)]),
          publicKey,
          message,
        ];
      case 2: {
        const mutated = Uint8Array.from(signature);
        const at = nextInt(64);
        mutated[at] = (mutated[at] ?? 0) ^ (0x01 << nextInt(8));
        return ['one bit flipped', mutated, publicKey, message];
      }
      case 3:
        return ['random signature', new Uint8Array([...randomPoint(), ...toLittleEndian(fromLittleEndian(nextBytes(32)) % GROUP_ORDER, 32)]), publicKey, message];
      case 4:
        return ['all-zero signature', new Uint8Array(64), publicKey, message];
      case 5:
        return ['R = A, S = 0', new Uint8Array([...publicKey, ...new Uint8Array(32)]), publicKey, message];
      case 6: {
        const key = fromHex(TORSION[index % TORSION.length]!);
        return ['R = A, S = 0 over a small-order key', new Uint8Array([...key, ...new Uint8Array(32)]), key, message];
      }
      case 7: {
        const y = BigInt(index % 19);
        const key = toLittleEndian(FIELD_PRIME + y, 32);
        return ['second spelling of a small y', new Uint8Array([...key, ...new Uint8Array(32)]), key, message];
      }
      case 8: {
        const r = Uint8Array.from(signature.subarray(0, 32));
        const key = Uint8Array.from(publicKey);
        r[31] = (r[31] ?? 0) | 0x80;
        key[31] = (key[31] ?? 0) | 0x80;
        return ['sign bit forced on both halves', new Uint8Array([...r, ...signature.subarray(32)]), key, message];
      }
      case 9:
        return ['short signature', signature.subarray(0, 63), publicKey, message];
      case 10:
        return ['short key', signature, publicKey.subarray(0, 31), message];
      default:
        return ['random key', signature, randomPoint(), message];
    }
  }

  it('answers every case the same under both readers, and names what the platform alone would have answered differently', () => {
    const disagreements: Array<{ readonly name: string; readonly strict: boolean; readonly guarded: boolean }> = [];
    let accepted = 0;
    let refusedBeforeTheEquation = 0;
    let platformAloneDiffers = 0;
    for (let index = 0; index < CASES; index += 1) {
      const [name, signature, publicKey, message] = buildCase(index);
      const strict = nobleStrictVerify(signature, message, publicKey);
      const guarded = preferredStrictVerify(signature, message, publicKey);
      if (strict) accepted += 1;
      if (refusalBeforeTheEquation(signature, publicKey) !== null) refusedBeforeTheEquation += 1;
      if (nativeAlone(signature, message, publicKey) !== strict) platformAloneDiffers += 1;
      if (strict !== guarded) disagreements.push({ name, strict, guarded });
    }
    // Both readers must answer alike on everything a caller can send by accident, and the sweep is the witness
    // that the clauses say the same rule the library's option says. The small-order R class above is the one
    // place they part, and it takes a signature only the holder of the secret key can produce.
    expect(disagreements).toEqual([]);
    expect(accepted).toBeGreaterThan(0);
    expect(refusedBeforeTheEquation).toBeGreaterThan(0);
    expect(platformAloneDiffers).toBeGreaterThan(0);
  });
});

describe('the proof-of-possession path in both readers', () => {
  // The wire format's own signing string, which is the input a gateway actually hands a verifier: 140 bytes of
  // method, target, timestamp, nonce and body digest rather than a bare message.
  const fields: PopFields = {
    ts: 1_772_000_000,
    nonce: new Uint8Array(POP_NONCE_BYTES).fill(0x5a),
    method: 'POST',
    target: '/v1/chat/completions',
    bodyDigestHex: EMPTY_BODY_SHA256_HEX,
  };
  const message = new TextEncoder().encode(popSigningString(fields));

  it('answers a signed request the same whichever reader is asked, and refuses the same tampering', () => {
    const { seed, publicKey } = keyWithKnownScalar(23);
    const signature = ed25519.sign(message, seed);
    expect(verifyPopSignature(fields, signature, publicKey, nobleStrictVerify)).toBe(true);
    expect(verifyPopSignature(fields, signature, publicKey, preferredStrictVerify)).toBe(true);
    const tampered: Array<readonly [string, Uint8Array, Uint8Array]> = [
      ['one byte of the signature changed', Uint8Array.from(signature, (byte) => byte ^ 0x01), publicKey],
      ['the same signature under another key', signature, keyWithKnownScalar(24).publicKey],
      ['a short signature', signature.subarray(0, 63), publicKey],
      ['a short key', signature, publicKey.subarray(0, 31)],
      ['the identity as a key', signature, fromHex(IDENTITY_ENCODING)],
    ];
    for (const [name, body, key] of tampered) {
      expect(verifyPopSignature(fields, body, key, nobleStrictVerify), name).toBe(
        verifyPopSignature(fields, body, key, preferredStrictVerify),
      );
      expect(verifyPopSignature(fields, body, key, preferredStrictVerify), name).toBe(false);
    }
  });

  it('refuses a proof whose point half is a small-order encoding, and names the reader that parts on it', () => {
    // The divergence the sweep cannot reach, asked through the wire format rather than as bare bytes: the
    // library's cofactored equation takes these, the runtime's exact one does not, and the default argument is
    // the library path so a caller that says nothing keeps the shipped answer.
    const { publicKey, scalar } = keyWithKnownScalar(7);
    const parts: string[] = [];
    for (const encoding of TORSION) {
      const rBytes = fromHex(encoding);
      const hash =
        fromLittleEndian(Uint8Array.from(sha512(Buffer.concat([Buffer.from(rBytes), Buffer.from(publicKey), message])))) % GROUP_ORDER;
      const body = new Uint8Array([...rBytes, ...toLittleEndian((hash * scalar) % GROUP_ORDER, 32)]);
      const throughLibrary = verifyPopSignature(fields, body, publicKey, nobleStrictVerify);
      const throughRuntime = verifyPopSignature(fields, body, publicKey, preferredStrictVerify);
      const byDefault = verifyPopSignature(fields, body, publicKey);
      expect(byDefault, `the default argument is the library path on ${encoding}`).toBe(throughLibrary);
      if (throughLibrary !== throughRuntime) parts.push(encoding);
    }
    expect(parts).toHaveLength(7);
  });
});

describe('the two readers answer the published corpus alike', () => {
  const bytes: Array<{ readonly where: string; readonly body: Uint8Array }> = [];
  for (const dir of ['receipts', 'exports', 'packs', 'manifests']) {
    let names: string[];
    try {
      names = readdirSync(`${DATA}/${dir}`);
    } catch {
      continue;
    }
    for (const name of names.filter((one) => one.endsWith('.cbor')).sort()) {
      bytes.push({ where: `${dir}/${name}`, body: Uint8Array.from(readFileSync(`${DATA}/${dir}/${name}`)) });
    }
  }

  it('every signing input the fixtures publish is admitted by both and refused by both under a wrong key', () => {
    expect(bytes.length).toBeGreaterThan(0);
    const { seed, publicKey } = keyWithKnownScalar(17);
    let admitted = 0;
    for (const one of bytes) {
      let document;
      try {
        document = decodeCoseSign1(one.body);
      } catch {
        continue;
      }
      const signingInput = encodeCanonical(['Signature1', document.protectedBytes, new Uint8Array(0), document.payloadBytes]);
      const fresh = ed25519.sign(signingInput, seed);
      expect(preferredStrictVerify(fresh, signingInput, publicKey), one.where).toBe(true);
      expect(nobleStrictVerify(fresh, signingInput, publicKey), one.where).toBe(true);
      expect(preferredStrictVerify(document.signature, signingInput, publicKey), `the carried signature under a foreign key, ${one.where}`).toBe(
        nobleStrictVerify(document.signature, signingInput, publicKey),
      );
      admitted += 1;
    }
    expect(admitted).toBe(bytes.length);
  });
});
