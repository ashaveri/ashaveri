import { describe, it, expect } from 'vitest';
import {
  generateSigningKey,
  keyId,
  issueReceipt,
  decodeReceipt,
  verifyReceipt,
  encodePayload,
  randomNonce,
  ReceiptError,
  equalBytes,
  signCoseSign1,
  decodeCoseSign1,
  encodeCanonical,
  COSE_SIGN1_TAG,
  claimsConfidentialDevice,
  receiptToJson,
  toHex,
} from '../src/index.js';
import type {
  CollateralSlot,
  Marking,
  ReceiptPayload,
  SigningKey,
  StampDisclosure,
} from '../src/index.js';
import * as receiptParser from '../src/receipt.js';
import {
  ALG_EDDSA,
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
  DECLARED_PROTECTED_LABELS,
  RECEIPT_CONTENT_TYPE,
  buildProtectedHeader,
} from '../src/cose.js';
import { ed25519 } from '@noble/curves/ed25519';
import { Tag, encode, defaultEncodeOptions, encodedNumber } from 'cbor2';
import { sortCoreDeterministic } from 'cbor2/sorts';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { cddlIntegerPositions, cddlRule, cddlRuleArms, cddlTextPositions, memberDeclarations, nestedRuleNames, readCddl } from './cddl.js';

// FIXED_NOW is whole seconds since the Unix epoch, the receipt format's own unit: it is assigned to
// `iat` below and handed to `verifyReceipt` as `nowSeconds`, both of which compare against seconds.
const FIXED_NOW = 1_772_000_000;

function samplePayload(overrides: Partial<ReceiptPayload> = {}): ReceiptPayload {
  return {
    v: 1,
    iss: 'dpl-9f2a41',
    ins: 'cvm-i-047f',
    iat: FIXED_NOW,
    nce: new Uint8Array(16).fill(0xab),
    req: sha256(new TextEncoder().encode('{"model":"m","messages":[]}')),
    res: sha256(new TextEncoder().encode('{"choices":[]}')),
    mdl: 'meta-llama/Llama-3.1-8B-Instruct',
    wts: sha256(new TextEncoder().encode('manifest')),
    meas: { tee: 'snp+gpucc', m: sha384(new TextEncoder().encode('launch-digest')) },
    att: { d: sha256(new Uint8Array(64).fill(2)), ts: FIXED_NOW - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
    epk: 3,
    tok: { p: 128, c: 64 },
    mk: { sch: 'none', d: sha256(new Uint8Array(0)) },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'this corpus takes no collateral in' },
      validity: { presence: 'not-taken-in', reason: 'this corpus records no validity context' },
    },
    itm: [{ t: FIXED_NOW, d: sha256(new TextEncoder().encode('{"choices":[]}')) }],
    ...overrides,
  };
}

describe('COSE_Sign1 receipt codec', () => {
  it('round-trips: issue, verify, decode agree', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);

    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.mdl).toBe(payload.mdl);
    expect(equalBytes(verified.payload.nce, payload.nce)).toBe(true);
    expect(equalBytes(keyId(key.publicKey), verified.header.kid)).toBe(true);

    const decoded = decodeReceipt(bytes);
    expect(decoded.payload.iss).toBe(payload.iss);
  });

  it('is canonical: re-encoding the decoded payload yields identical bytes', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);
    const decoded = decodeReceipt(bytes);
    const payloadBytes = encodePayload(decoded.payload);
    // payloadBytes in the COSE structure is exactly the canonical encoding
    expect(equalBytes(payloadBytes, decoded.cose.payloadBytes)).toBe(true);
    const bytes2 = issueReceipt(decoded.payload, key);
    expect(equalBytes(bytes, bytes2)).toBe(true);
  });

  it('rejects a tampered payload byte with INVALID_SIGNATURE', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const tampered = new Uint8Array(bytes);
    tampered[tampered.length - 10]! ^= 0x01;
    expectErrorCode(() => verifyReceipt(tampered, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'INVALID_SIGNATURE');
  });

  it('rejects a signature from a different key', () => {
    const signer = generateSigningKey();
    const other = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), signer);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: other.publicKey, nowSeconds: FIXED_NOW }), 'KID_MISMATCH');
  });

  it('resolves keys via resolveKey by kid', () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const resolver = (kid: Uint8Array) => (equalBytes(kid, keyId(key.publicKey)) ? key.publicKey : undefined);
    expect(() => verifyReceipt(bytes, { resolveKey: resolver, nowSeconds: FIXED_NOW })).not.toThrow();
    const badResolver = () => other.publicKey;
    expectErrorCode(() => verifyReceipt(bytes, { resolveKey: badResolver, nowSeconds: FIXED_NOW }), 'KID_MISMATCH');
    expectErrorCode(() => verifyReceipt(bytes, { resolveKey: () => undefined, nowSeconds: FIXED_NOW }), 'UNKNOWN_KEY');
  });

  it('enforces nonce echo', () => {
    const key = generateSigningKey();
    const nonce = randomNonce();
    const bytes = issueReceipt(samplePayload({ nce: nonce }), key);
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, expectedNonce: nonce, nowSeconds: FIXED_NOW })).not.toThrow();
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, expectedNonce: randomNonce(), nowSeconds: FIXED_NOW }),
      'NONCE_MISMATCH',
    );
  });

  it('enforces receipt and evidence freshness windows', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const nowSeconds = FIXED_NOW + 3600;
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds, freshnessSeconds: 7200, evidenceFreshnessSeconds: 7200 })).not.toThrow();
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds, freshnessSeconds: 60 }), 'STALE_RECEIPT');
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds, freshnessSeconds: 7200, evidenceFreshnessSeconds: 60 }),
      'STALE_EVIDENCE',
    );
  });

  it('refuses a verification time that is not a reading of a seconds clock', () => {
    // Two spellings of one instant, handed over the same bytes under the same window. The refused case
    // is the milliseconds figure, a thousand times the seconds the receipt is stamped in, and the
    // accepted case is the same instant counted whole: a guard that refused the first while refusing
    // the second as well would simply be refusing every clock, and nothing in the suite would say
    // which of the two it had met.
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const refusal = expectFailure(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW * 1000, freshnessSeconds: 60 }),
      'VERIFICATION_TIME_OUT_OF_RANGE',
    );
    // Both ends of the band are in the sentence, because whoever handed the figure has to be able to
    // see which side of it their number fell outside without opening this file.
    expect(refusal.message).toContain('1000000000');
    expect(refusal.message).toContain('4294967295');
    expect(refusal.message).toContain('1772000000000');
    expect(() =>
      verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW, freshnessSeconds: 60 }),
    ).not.toThrow();
    // The reading is refused at the entry rather than inside a window, so a caller who opened neither
    // is still told their argument is impossible instead of being handed a verified receipt they
    // weighed nothing against.
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW * 1000 }),
      'VERIFICATION_TIME_OUT_OF_RANGE',
    );
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW })).not.toThrow();
  });

  it('rejects structurally invalid payloads with BAD_PAYLOAD', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    // A 15-byte nonce satisfies the field's type but not the codec's fixed 16-byte
    // length, so the payload this line builds is structurally invalid.
    const bad = { ...payload, nce: new Uint8Array(15) };
    const bytes = issueReceipt(bad as ReceiptPayload, key);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');
  });

  it('rejects a negative timestamp with BAD_PAYLOAD', () => {
    const key = generateSigningKey();
    const base = samplePayload();
    // The spec fixes every integer as non-negative, so a signed document that breaks
    // that rule is malformed even when its signature is valid.
    const negativeIat = issueReceipt(samplePayload({ iat: -1 }), key);
    expectErrorCode(() => verifyReceipt(negativeIat, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');
    const negativeEvidenceTs = issueReceipt(samplePayload({ att: { ...base.att, ts: -1 } }), key);
    expectErrorCode(
      () => verifyReceipt(negativeEvidenceTs, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      'BAD_PAYLOAD',
    );
  });

  it('names the failing part of an unparseable document', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const cose = decodeCoseSign1(bytes);
    const wrap = (parts: unknown[]): Uint8Array =>
      new Uint8Array(encodeCanonical(new Tag(COSE_SIGN1_TAG, parts)));
    // Each of these makes the CBOR reader throw its own exception. A caller branches
    // on the error code, so an unclassified throw is a crash, not a verdict.
    expectErrorCode(() => decodeReceipt(new Uint8Array(0)), 'MALFORMED_CBOR');
    expectErrorCode(() => decodeReceipt(bytes.slice(0, 6)), 'MALFORMED_CBOR');
    expectErrorCode(
      () => decodeReceipt(wrap([new Uint8Array(0), new Map(), cose.payloadBytes, cose.signature])),
      'BAD_PROTECTED_HEADER',
    );
    expectErrorCode(
      () => decodeReceipt(wrap([cose.protectedBytes, new Map(), new Uint8Array(0), cose.signature])),
      'BAD_PAYLOAD',
    );
  });

  it('carries a 48-byte hardware measurement', () => {
    const key = generateSigningKey();
    const launchDigest = new Uint8Array(48).fill(7);
    const bytes = issueReceipt(samplePayload({ meas: { tee: 'tdx', m: launchDigest } }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.meas.m).toHaveLength(48);
    expect(equalBytes(verified.payload.meas.m, launchDigest)).toBe(true);
  });

  it('carries a 32-byte software measurement', () => {
    const key = generateSigningKey();
    const digest = sha256(new TextEncoder().encode('deployment image'));
    const bytes = issueReceipt(samplePayload({ meas: { tee: 'software', m: digest } }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.meas.tee).toBe('software');
    expect(equalBytes(verified.payload.meas.m, digest)).toBe(true);
  });

  it('carries the TDX measurement for a claim that also names an accelerator', () => {
    const key = generateSigningKey();
    const mrtd = new Uint8Array(48).fill(11);
    const bytes = issueReceipt(samplePayload({ meas: { tee: 'tdx+gpucc', m: mrtd } }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.meas.tee).toBe('tdx+gpucc');
    expect(equalBytes(verified.payload.meas.m, mrtd)).toBe(true);
    expectErrorCode(
      () => issueReceipt(samplePayload({ meas: { tee: 'tdx+gpucc', m: new Uint8Array(32) } }), key),
      'BAD_PAYLOAD',
    );
  });

  it('promises a device report exactly for the kinds that name an accelerator', () => {
    expect(claimsConfidentialDevice('snp+gpucc')).toBe(true);
    expect(claimsConfidentialDevice('tdx+gpucc')).toBe(true);
    expect(claimsConfidentialDevice('snp')).toBe(false);
    expect(claimsConfidentialDevice('tdx')).toBe(false);
    expect(claimsConfidentialDevice('software')).toBe(false);
  });

  it('refuses a receipt signed under a card-named composite label', () => {
    // Signed past issueReceipt rather than built through it: the point is that a
    // verifier does not recognise the label, so the bytes have to exist first.
    const key = generateSigningKey();
    const foreign = signCoseSign1(
      encodePayload(samplePayload({ meas: { tee: 'snp+h100cc' as never, m: new Uint8Array(48).fill(7) } })),
      key,
    );
    let caught: ReceiptError | null = null;
    try {
      verifyReceipt(foreign, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    } catch (e) {
      caught = e as ReceiptError;
    }
    expect(caught?.code).toBe('BAD_PAYLOAD');
    expect(caught?.message).toContain('meas.tee is not a known environment kind');
  });

  it('refuses to issue a measurement whose width contradicts its kind', () => {
    const key = generateSigningKey();
    expectErrorCode(
      () => issueReceipt(samplePayload({ meas: { tee: 'snp', m: new Uint8Array(32) } }), key),
      'BAD_PAYLOAD',
    );
    expectErrorCode(
      () => issueReceipt(samplePayload({ meas: { tee: 'software', m: new Uint8Array(48) } }), key),
      'BAD_PAYLOAD',
    );
  });

  it('rejects a signed receipt that claims a TEE with a software-width measurement', () => {
    const key = generateSigningKey();
    // Built by hand: issueReceipt would refuse this payload, and a hostile or buggy
    // issuer is exactly who the parser has to catch.
    const payload = samplePayload({ meas: { tee: 'snp', m: new Uint8Array(32) } });
    const bytes = signCoseSign1(encodePayload(payload), key);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');
  });

  it('generates a deterministic kid (sha256 of public key)', () => {
    const key = generateSigningKey();
    expect(key.kid).toEqual(sha256(key.publicKey));
    const key2 = generateSigningKey();
    expect(equalBytes(key.kid, key2.kid)).toBe(false);
  });
});

/**
 * The three labels `receipt.cddl` declares, spelled out here rather than borrowed from
 * `buildProtectedHeader`, because the cases below add to them and take from them. The equality
 * assertion that opens the first case is what proves this map and that function write one document,
 * so the hand-built control cannot quietly be a lookalike of the format.
 */
function declaredProtectedHeader(kid: Uint8Array): Map<unknown, unknown> {
  return new Map<unknown, unknown>([
    [COSE_HEADER_ALG, ALG_EDDSA],
    [COSE_HEADER_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
    [COSE_HEADER_KID, kid],
  ]);
}

/**
 * A `COSE_Sign1` whose signature covers the header maps this call names, rather than the two
 * `signCoseSign1` builds for itself. The point is that whatever sits in the protected bstr is
 * authenticated: a refusal over such bytes is a verifier declining the document it was handed, and an
 * acceptance is a signature that genuinely holds over them. The unprotected map is not in the
 * `Sig_structure` at all, so an entry handed for it travels with the document without being signed.
 */
function signWithHeaders(
  payloadBytes: Uint8Array,
  key: SigningKey,
  protectedHeader: Map<unknown, unknown>,
  unprotectedHeader: Map<unknown, unknown> = new Map(),
): Uint8Array {
  const protectedBytes = encodeCanonical(protectedHeader);
  const signature = ed25519.sign(
    encodeCanonical(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]),
    key.privateKey,
  );
  return encodeCanonical(new Tag(COSE_SIGN1_TAG, [protectedBytes, unprotectedHeader, payloadBytes, signature]));
}

/** The refusal the closed signed header answers with, in full, so a reworded one lands here. */
const UNDECLARED_LABEL_REFUSAL =
  'protected header does not hold exactly the parameters the format declares: it carries a label the format does not define:';

describe('the protected header closes and the unprotected one does not', () => {
  it('refuses an undeclared label inside the signed header and takes the same label outside it', () => {
    const key = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());

    // The control first, because it is the half that decides whether the refusal below means
    // anything: these are bytes this file writes rather than bytes `issueReceipt` writes, so the
    // header has to be the format's own and the signature has to hold over it. Otherwise the case
    // under this line would be refusing a broken document while calling it an undeclared label.
    expect(equalBytes(encodeCanonical(declaredProtectedHeader(key.kid)), buildProtectedHeader(key.kid))).toBe(true);
    const declared = signWithHeaders(payloadBytes, key, declaredProtectedHeader(key.kid));
    const verified = verifyReceipt(declared, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.mdl).toBe('meta-llama/Llama-3.1-8B-Instruct');
    expect(equalBytes(verified.cose.payloadBytes, payloadBytes)).toBe(true);
    // And the control is a signature check rather than a reader that always answers yes: one byte of
    // the signature moved, the same document comes back refused for its signature and not for its
    // header, which is what makes the acceptance above evidence about the label below.
    const moved = new Uint8Array(declared);
    moved[moved.length - 1]! ^= 0x01;
    expectFailure(() => verifyReceipt(moved, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'INVALID_SIGNATURE');

    // One more label and the same rule for making the bytes. Label 5 is not one `receipt.cddl` names,
    // and it is inside the `Sig_structure`, so a reader that took the three it knows and returned
    // those handed on a smaller document than the one the issuer signed. It is refused by number.
    const fifth = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [5, 'x']]);
    const refused = signWithHeaders(payloadBytes, key, fifth);
    const failure = expectFailure(
      () => verifyReceipt(refused, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      'BAD_PROTECTED_HEADER',
    );
    expect(failure.message).toBe(`${UNDECLARED_LABEL_REFUSAL} 5`);
    // Which way the document is opened changes nothing. The header is read before a key is looked up
    // and before a signature is checked, so an unread receipt answers as a verified one does.
    expectFailure(() => decodeReceipt(refused), 'BAD_PROTECTED_HEADER');

    // The same refusal for a label carrying the other sign RFC 9052 section 3.1 admits, which is the
    // shape a closure by number has to survive and a range check would not: -1 is as legal a header key
    // as 5 is, and this format declares neither. It travels here because the set this refusal is built
    // from is derived from `receipt.cddl` in `schema.test.ts`, and a reader of that file that saw only
    // unsigned digits would keep the two lists equal over a label like this one.
    const negative = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [-1, 0]]);
    const negativeFailure = expectFailure(
      () => verifyReceipt(signWithHeaders(payloadBytes, key, negative), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      'BAD_PROTECTED_HEADER',
    );
    expect(negativeFailure.message).toBe(`${UNDECLARED_LABEL_REFUSAL} -1`);

    // The mirror, and the reason the two halves are one case: the same label and the same value in
    // the map the signature does not cover. The format declares that one open by decision, so this
    // document verifies and the entry arrives intact. It is the case that says the refusal above
    // stopped at the signed part rather than reaching the envelope.
    const unsignedFifth = signWithHeaders(
      payloadBytes,
      key,
      declaredProtectedHeader(key.kid),
      new Map<unknown, unknown>([[5, 'x']]),
    );
    const passed = verifyReceipt(unsignedFifth, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(passed.cose.unprotected.get(5)).toBe('x');
  });

  it('refuses a declared parameter that is absent, which is the other half of the same sentence', () => {
    const key = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());
    // Every label this map still carries is one the format defines, so the closure check above passes
    // and the refusal below is the required-parameter rule. Those two refusals answer under one code,
    // and this is the case that says closing the map did not replace asking for what it must hold. One
    // declared parameter is not in that pair, and the case after this one is what keeps the sentence
    // about one code from being read as a sentence about every header fault.
    const noKid = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid)]);
    noKid.delete(COSE_HEADER_KID);
    const failure = expectFailure(
      () => verifyReceipt(signWithHeaders(payloadBytes, key, noKid), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      'BAD_PROTECTED_HEADER',
    );
    expect(failure.message).toContain('kid must be a 32-byte bstr');
  });

  it('answers a missing alg under its own code, not under the header code', () => {
    const key = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());
    // The same edit to the map that the case above makes to `kid`, one label shorter: every label left
    // is declared, so the closure rule passes, and the parameter that is gone is `alg`. That answers
    // `UNSUPPORTED_ALG`, which is what `docs/error-codes.md`'s row for the code says it covers, and not
    // `BAD_PROTECTED_HEADER`, because a header with no `alg` is not claiming to be a different map, it
    // is saying nothing about which suite produced the signature. The two codes stay separate rows, and
    // both are terminal, so this case pins a distinction a caller reads off the code rather than one it
    // acts on differently.
    const noAlg = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid)]);
    noAlg.delete(COSE_HEADER_ALG);
    const failure = expectFailure(
      () => verifyReceipt(signWithHeaders(payloadBytes, key, noAlg), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      'UNSUPPORTED_ALG',
    );
    expect(failure.message).toContain('alg must be an integer label, got undefined');
    // And the other shape of the same parameter, a suite this format does not sign with, answers under
    // that code too: the split is between the map and the algorithm, not between an absent `alg` and a
    // wrong one.
    const wrongAlg = new Map<unknown, unknown>(declaredProtectedHeader(key.kid));
    wrongAlg.set(COSE_HEADER_ALG, -7);
    expectFailure(
      () => verifyReceipt(signWithHeaders(payloadBytes, key, wrongAlg), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      'UNSUPPORTED_ALG',
    );
  });

  it('reads no claim out of the unprotected map, over two documents that differ only there', () => {
    const key = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());
    const signed = declaredProtectedHeader(key.kid);
    // Two documents, one signature, and everything the parser reads held identical between them except
    // the map outside the signature. The second fills that map with a rival for every read the parser
    // makes: an `alg` naming a suite this format does not sign with, a `kid` of the right width and the
    // wrong key, a `typ` that is not this format, and two payload members spelled out as text keys. What
    // this measures is therefore not whether an empty map parses, which would be true of a parser that
    // ignored the envelope entirely, but whether anything at all travels from that map into the verdict
    // on a document that verifies.
    const rival = new Map<unknown, unknown>([
      [COSE_HEADER_ALG, -7],
      [COSE_HEADER_KID, new Uint8Array(32).fill(9)],
      [COSE_HEADER_CONTENT_TYPE, 'application/cbor'],
      ['mdl', 'a-model-the-sender-chose'],
      ['iat', 1],
    ]);
    const openBytes = signWithHeaders(payloadBytes, key, signed, new Map());
    const rivalBytes = signWithHeaders(payloadBytes, key, signed, rival);
    const empty = verifyReceipt(openBytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    const filled = verifyReceipt(rivalBytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    // The premise first, and about the bytes: two documents, not one document read twice, and the only
    // difference between them is the content of that one map. The signature is the same bytes in both,
    // because the `Sig_structure` covers the protected bytes, the external AAD and the payload and
    // nothing else, so anything that reached a verdict from the map on the left would have arrived
    // through the envelope rather than through what was signed.
    expect(equalBytes(rivalBytes, openBytes)).toBe(false);
    expect(equalBytes(filled.cose.signature, empty.cose.signature)).toBe(true);
    expect(equalBytes(filled.cose.protectedBytes, empty.cose.protectedBytes)).toBe(true);
    expect(equalBytes(filled.cose.payloadBytes, empty.cose.payloadBytes)).toBe(true);
    expect(filled.cose.unprotected.size).toBe(5);
    expect(empty.cose.unprotected.size).toBe(0);
    // And the rival arrived intact rather than being emptied on the way in: the map is handed to the
    // caller as the sender wrote it, which is what makes the assertions that follow about the reads the
    // parser makes and not about a map that stopped existing before any read happened.
    expect(filled.cose.unprotected.get(COSE_HEADER_ALG)).toBe(-7);
    expect(filled.cose.unprotected.get('mdl')).toBe('a-model-the-sender-chose');
    // The two halves the ruling rests on: the payload the parser parses, and the header it projects for
    // its caller, are one document across both bytes. Named as the signed values too, because equality
    // between the two on its own would still hold if a reader ever preferred the unprotected map, and it
    // is that preference this case keeps out of the package.
    expect(filled.payload).toEqual(empty.payload);
    expect(filled.header).toEqual(empty.header);
    expect(filled.payload.mdl).toBe('meta-llama/Llama-3.1-8B-Instruct');
    expect(filled.header.alg).toBe(ALG_EDDSA);
    expect(equalBytes(filled.header.kid, key.kid)).toBe(true);
    // The same answer from a reader that never reaches a signature check at all, which is the other way
    // a claim could be handed to a caller: an unread receipt is read on its face, and the map above is
    // not covered by the signature that would otherwise have to be made over it.
    const unread = decodeReceipt(rivalBytes);
    expect(unread.payload).toEqual(empty.payload);
    expect(unread.header).toEqual(empty.header);
  });

  it('names a label it cannot read without letting it write the message', () => {
    const key = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());
    // A COSE header label is an integer, so a text one is undeclared twice over, and this is the
    // refusal whose quoted name comes out of bytes whoever sent the receipt wrote. It lives under the
    // promise `ReceiptError` makes about every detail: the sentence is fixed, only the quote is
    // bounded, and no control character survives, so a label cannot end the log line it is written
    // into. Taken at four thousand characters, the width the payload-level case takes it at too.
    const hostile = `typ\u001b[2J${'q'.repeat(4_000)}`;
    const textLabel = expectFailure(
      () =>
        decodeReceipt(
          signWithHeaders(payloadBytes, key, new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [hostile, 'x']])),
        ),
      'BAD_PROTECTED_HEADER',
    );
    expect(textLabel.message).toContain('a label the format does not define:');
    expect(textLabel.message).not.toMatch(/[\p{Cc}\p{Cf}\u{2028}\u{2029}]/u);
    expect(textLabel.message).toContain('\\u001b');
    expect(textLabel.message.length).toBeLessThan(400);
    expect(textLabel.message).toContain('...');

    // And a key that is neither, described by what it is rather than by what an object's default
    // `toString` turns it into.
    const bstrLabel = expectFailure(
      () =>
        decodeReceipt(
          signWithHeaders(
            payloadBytes,
            key,
            new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [new Uint8Array([1, 2, 3]), 'x']]),
          ),
        ),
      'BAD_PROTECTED_HEADER',
    );
    expect(bstrLabel.message).toBe(`${UNDECLARED_LABEL_REFUSAL} a bstr label of length 3`);

    // And the two keys that are integers, just not integers a label can be: a tag 2 bignum, and a CBOR
    // integer the encoder writes in major type 0 but too wide for the decoder to hand back as a
    // `number`, both arrive as `bigint`, which is an integer outside the range a COSE label occupies.
    // Calling either "not an integer" points whoever reads the log at a type bug rather than at the
    // label space, which is the one place the document is wrong. The second is here because it is not a
    // bignum on the wire at all, and a message that named it one would be the same defect wearing a
    // different word.
    const bignumLabel = expectFailure(
      () =>
        decodeReceipt(
          signWithHeaders(
            payloadBytes,
            key,
            new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [2n ** 64n, 'x']]),
          ),
        ),
      'BAD_PROTECTED_HEADER',
    );
    expect(bignumLabel.message).toBe(
      `${UNDECLARED_LABEL_REFUSAL} an integer outside the range a COSE label occupies`,
    );
    const wideIntLabel = expectFailure(
      () =>
        decodeReceipt(
          signWithHeaders(
            payloadBytes,
            key,
            new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [2n ** 53n + 7n, 'x']]),
          ),
        ),
      'BAD_PROTECTED_HEADER',
    );
    expect(wideIntLabel.message).toBe(
      `${UNDECLARED_LABEL_REFUSAL} an integer outside the range a COSE label occupies`,
    );
  });
});

/**
 * The digest an unmarked receipt carries: the marked region is empty, so `mk.d` is the digest of
 * no bytes at all. Spelled out here rather than derived because it is the value that turns "not
 * marked" into a claim a reader can check instead of a hole where a field would have been.
 */
const EMPTY_REGION_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** Stands in for the response bytes a `provenance-v1` mark occupies. */
const MARKED_REGION = new TextEncoder().encode(
  '{"ashaveri":{"marking":{"sch":"ashaveri/provenance-v1","gen":"ai","at":1772000000}}}',
);

function markedPayload(mk: Marking = { sch: 'provenance-v1', d: sha256(MARKED_REGION) }): ReceiptPayload {
  return { ...samplePayload(), mk };
}

/**
 * The document this corpus carries at its fullest: a marked receipt whose disclosure names a source
 * nobody measured, whose anchor holds one piece of appraisal context and states the other as never
 * taken in, and whose item list holds one item. Every sweep below that reaches inside `sd`, `cva` or
 * `itm` reads this document, because it is the one that carries all four of the members a receipt
 * states about itself.
 */
function stampedPayload(): ReceiptPayload {
  return {
    ...markedPayload(),
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'held', sha256: sha256(new TextEncoder().encode('collateral bytes')) },
      validity: { presence: 'not-taken-in', reason: 'the collector read no window' },
    },
    itm: [{ t: FIXED_NOW, d: sha256(new TextEncoder().encode('{"a":1}')) }],
  };
}

/**
 * The members the corpus carries as an array of maps rather than as a map. Read off the bytes the
 * writer builds rather than written out beside them, because the index a refusal names for an element
 * is the reader's own spelling and this file quotes it.
 */
function elementMembers(): string[] {
  const members = membersOf(stampedPayload());
  return [...members.keys()].filter((key) => Array.isArray(members.get(key)));
}

/**
 * The position a swept or edited name reaches. A member of a list is named with the index the reader
 * reads it at, which is how the refusal this file quotes and the edit this file makes agree on which
 * entry of one response they are both talking about. A name that is not below a list member is its own
 * position, so the same call answers for `att.ts`, for `cva.col` and for `itm`.
 */
function positionOf(where: string): string {
  const parts = where.split('.');
  const head = parts[0]!;
  const rest = parts.slice(1);
  if (!elementMembers().includes(head)) return where;
  return rest.length === 0 ? `${head}[0]` : `${head}[0].${rest.join('.')}`;
}

/**
 * A payload's members as the codec encodes them, spelled out a second time on purpose. A case that
 * has to hand over bytes no typed payload can express changes one of these, and the agreement
 * between this map and `encodePayload` is then two independent spellings of the same format.
 */
function membersOf(payload: ReceiptPayload): Map<string, unknown> {
  const members: Array<[string, unknown]> = [
    ['v', payload.v],
    ['iss', payload.iss],
    ['ins', payload.ins],
    ['iat', payload.iat],
    ['nce', payload.nce],
    ['req', payload.req],
    ['res', payload.res],
    ['mdl', payload.mdl],
    ['wts', payload.wts],
    ['meas', new Map<string, unknown>([['tee', payload.meas.tee], ['m', payload.meas.m]])],
    ['att', new Map<string, unknown>([['d', payload.att.d], ['ts', payload.att.ts], ['url', payload.att.url]])],
    ['epk', payload.epk],
    ['tok', new Map<string, unknown>([['p', payload.tok.p], ['c', payload.tok.c]])],
  ];
  members.push(['mk', new Map<string, unknown>([['sch', payload.mk.sch], ['d', payload.mk.d]])]);
  const slot = (one: CollateralSlot): Map<string, unknown> =>
    one.presence === 'held'
      ? new Map<string, unknown>([['p', one.presence], ['d', one.sha256]])
      : new Map<string, unknown>([['p', one.presence], ['r', one.reason]]);
  members.push(
    ['sd', new Map<string, unknown>([['name', payload.sd.name], ['unc', payload.sd.uncertaintySeconds]])],
    ['cva', new Map<string, unknown>([['col', slot(payload.cva.collateral)], ['val', slot(payload.cva.validity)]])],
    ['itm', payload.itm.map((one) => new Map<string, unknown>([['t', one.t], ['d', one.d]]))],
  );
  return new Map<string, unknown>(members);
}

/**
 * Signed past `issueReceipt`, which refuses the payloads the parser is required to catch: an absent
 * member, an unexpected one, a label outside the registry, a version nobody has declared. The map
 * is read-only and its keys are unknown-typed because the documents this file builds include one
 * whose key is not a text label at all, which no typed payload can hold.
 */
function signMembers(members: ReadonlyMap<unknown, unknown>, key: SigningKey): Uint8Array {
  return signCoseSign1(encodeCanonical(members), key);
}

describe('the receipt payload and the versions a call accepts', () => {
  it('round-trips a well-formed marked receipt', () => {
    const key = generateSigningKey();
    const payload = markedPayload();
    const verified = verifyReceipt(issueReceipt(payload, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW });

    expect(verified.payload.v).toBe(1);
    expect(verified.payload.mk.sch).toBe('provenance-v1');
    expect(equalBytes(verified.payload.mk.d, sha256(MARKED_REGION))).toBe(true);
    // Every v1 field still arrives, and the re-encode is the bytes that were signed.
    expect(verified.payload.mdl).toBe(payload.mdl);
    expect(equalBytes(encodePayload(verified.payload), verified.cose.payloadBytes)).toBe(true);
  });

  it('encodes a marked payload exactly as the format lays out its members', () => {
    const payload = markedPayload();
    expect(equalBytes(encodePayload(payload), encodeCanonical(membersOf(payload)))).toBe(true);
  });

  it("parses an unmarked receipt carrying the empty region's digest", () => {
    const key = generateSigningKey();
    const empty = sha256(new Uint8Array(0));
    expect(toHex(empty)).toBe(EMPTY_REGION_SHA256_HEX);
    const bytes = issueReceipt(markedPayload({ sch: 'none', d: empty }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });

    expect(verified.payload.mk.sch).toBe('none');
    expect(toHex(verified.payload.mk.d)).toBe(EMPTY_REGION_SHA256_HEX);
  });

  it('refuses a payload with no mk as a payload failure, not as an unmarked receipt', () => {
    const key = generateSigningKey();
    const members = membersOf(markedPayload());
    members.delete('mk');
    const bytes = signMembers(members, key);
    // The detail is the assertion here. Every member this document is missing is also a wrong-kind
    // read, so the code alone would still be BAD_PAYLOAD if the requirement that `mk` be present
    // were deleted: only the sentence says the refusal was reached for that reason.
    const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
    expect(failure.message).toContain('v1 requires an mk member');
  });

  it('refuses a marking scheme outside the registry it reads', () => {
    const key = generateSigningKey();
    const members = membersOf(markedPayload());
    // A label one step on from a scheme this package has never been told about: the parser's
    // accepted set is `none` and `provenance-v1`, and guessing at the rest is the confusion the
    // refusal exists to prevent.
    members.set('mk', new Map<string, unknown>([['sch', 'provenance-v2'], ['d', sha256(MARKED_REGION)]]));
    const bytes = signMembers(members, key);
    // And here the detail says the refusal is the scheme's, reached with `mk` present and shaped:
    // a payload failure and this one are different answers, and only the message tells them apart.
    const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'UNSUPPORTED_SCHEME');
    expect(failure.message).toContain("marking scheme 'provenance-v2'");
  });

  it('refuses a document bearing a retired version and names the number it read', () => {
    const key = generateSigningKey();
    // The retired numbers get a version answer, not a structural one: these bytes carry every member
    // the format defines and move only the `v`, so a refusal here that named a member would say the
    // document was incomplete when what it says is that this build reads no such version. Each number
    // arrives in the message, and neither reading of the document is left to fall through.
    for (const retired of [2, 3]) {
      const members = membersOf(stampedPayload());
      members.set('v', retired);
      const bytes = signMembers(members, key);
      const failure = expectFailure(
        () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
        'UNSUPPORTED_VERSION',
      );
      expect(failure.message).toContain(`receipt payload version ${retired} is not a format this package reads`);
      expectErrorCode(() => decodeReceipt(bytes), 'UNSUPPORTED_VERSION');
    }
  });

  it('refuses any member the payload version does not define, not only the marking one', () => {
    const key = generateSigningKey();
    // One list per version rather than a case per name, so the check that fires for one name fires
    // for every other: an extra member that looks like it could belong to this format, and one that
    // plainly does not belong to any version of it.
    for (const [name, value] of [
      ['enc', new Uint8Array(32).fill(9)],
      ['not_a_member', 'x'],
    ] as Array<[string, unknown]>) {
      const members = membersOf(markedPayload());
      members.set(name, value);
      const failure = expectFailure(
        () => verifyReceipt(signMembers(members, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
      );
      expect(failure.message, `${name} on the payload`).toContain(`member version 1 does not define: '${name}'`);
    }
    // A key that is not a text label is not a member either, and no CDDL map admits one.
    const foreignKey = new Map<unknown, unknown>([...membersOf(samplePayload()), [new Uint8Array([7]), 'x']]);
    const failure = expectFailure(
      () => verifyReceipt(signMembers(foreignKey, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
    );
    expect(failure.message).toContain('a bstr key of length 1');
  });

  it('names a key the bytes chose without letting it write the message', () => {
    const key = generateSigningKey();
    // The closedness detail is the one part of this refusal whose text comes out of bytes whoever
    // sent the receipt wrote, so it lives under the promise `ReceiptError` makes about every quoted
    // detail: the sentence is fixed and only the quote is bounded, and no control character survives
    // the message, so a key cannot end the log line it is written into or drive a terminal. That
    // promise is what lets this site hand back a name it does not control, and a tstr key is as long
    // as the document carrying it, so this is the case taken at four thousand characters with an
    // escape sequence inside it.
    const hostile = `mk\u001b[2J${'q'.repeat(4_000)}`;
    const members = new Map<unknown, unknown>([...membersOf(samplePayload()), [hostile, 'x']]);
    const failure = expectFailure(
      () => verifyReceipt(signMembers(members, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
    );
    expect(failure.message).toContain('payload carries a member version 1 does not define:');
    // One line of visible text, and the escape sequence arrives as a name for itself rather than as
    // a command: what a reader sees is the six characters `u001b` behind a backslash.
    expect(failure.message).not.toMatch(/[\p{Cc}\p{Cf}\u{2028}\u{2029}]/u);
    expect(failure.message).toContain('\\u001b');
    // Bounded, and announced as bounded: four thousand characters of name reach the reader as the
    // head of the detail and an ellipsis, which says text was dropped rather than that the key was
    // short. The cap is 200 characters of the detail and the fixed sentence around it is shorter
    // still, so a message this package builds cannot run to the length of the document.
    expect(failure.message.length).toBeLessThan(400);
    expect(failure.message).toContain('...');
  });

  it('refuses a v that is not an integer, which is the malformed half of the version read', () => {
    const key = generateSigningKey();
    // Both spellings of "not an integer at all" land here, and neither is the version code: a
    // document a reader cannot take a version from is a malformed payload, which is what the spec
    // and the code table both say. The `v: 4` case further down this block proves the other half,
    // that an integer this package does not read is a version answer rather than a payload one.
    const textVersion = membersOf(samplePayload());
    textVersion.set('v', '1');
    const text = signMembers(textVersion, key);
    expect(expectFailure(() => decodeReceipt(text)).message).toContain('v must be an integer receipt version');

    const absentVersion = membersOf(samplePayload());
    absentVersion.delete('v');
    const absent = signMembers(absentVersion, key);
    expect(expectFailure(() => decodeReceipt(absent)).message).toContain('v must be an integer receipt version');
  });

  it('refuses a receipt a caller narrowed away with the code for versions', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(markedPayload(), key);
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW, acceptedVersions: [] }),
      'UNSUPPORTED_VERSION',
    );
  });

  it('refuses a version this package cannot parse with the same code', () => {
    const key = generateSigningKey();
    const members = membersOf(samplePayload());
    members.set('v', 4);
    const bytes = signMembers(members, key);
    // One code for both refusals on purpose: which side of a boundary a number sits on is a fact
    // about releases, and two answers would let a caller find it out. `4` is the sentinel because no
    // number below it is one: `2` and `3` are retired, `1` is read, and a document wearing a version
    // this reader does grasp but whose members do not agree with it is a payload answer, which is the
    // case the two halves below keep apart.
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'UNSUPPORTED_VERSION');
    expectErrorCode(() => decodeReceipt(bytes), 'UNSUPPORTED_VERSION');

    // Closedness is settled after the version, so these two refusals never compete for one document:
    // a version a reader cannot take answers with the version code whichever members it carries, and
    // so does a version a caller narrowed away. Without this, the one answer the format promises
    // would depend on what else the bytes happened to hold.
    const unreadable = membersOf(samplePayload());
    unreadable.set('v', 4);
    unreadable.set('mk', new Map<string, unknown>());
    const unreadableBytes = signMembers(unreadable, key);
    expectErrorCode(() => verifyReceipt(unreadableBytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'UNSUPPORTED_VERSION');
    expectErrorCode(() => decodeReceipt(unreadableBytes), 'UNSUPPORTED_VERSION');

    const narrowed = membersOf(markedPayload());
    narrowed.set('not_a_member', 'x');
    const narrowedBytes = signMembers(narrowed, key);
    expectErrorCode(
      () => verifyReceipt(narrowedBytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW, acceptedVersions: [] }),
      'UNSUPPORTED_VERSION',
    );
    expectErrorCode(() => decodeReceipt(narrowedBytes, { acceptedVersions: [] }), 'UNSUPPORTED_VERSION');
  });

  it('refuses the document when the accepted set is empty', () => {
    const key = generateSigningKey();
    const marked = issueReceipt(markedPayload(), key);
    const stamped = issueReceipt(stampedPayload(), key);
    for (const bytes of [marked, stamped]) {
      expectErrorCode(
        () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW, acceptedVersions: [] }),
        'UNSUPPORTED_VERSION',
      );
      expectErrorCode(() => decodeReceipt(bytes, { acceptedVersions: [] }), 'UNSUPPORTED_VERSION');
    }
  });

  it('verifies a receipt with nothing set and every member it states read back', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });

    expect(verified.payload.v).toBe(1);
    expect(equalBytes(encodePayload(verified.payload), verified.cose.payloadBytes)).toBe(true);
    // The seventeen members are the whole document, in the order the format lists them and the twin
    // writes them: a receipt states its marking, its source, its anchor and its items or it states
    // nothing about them, and its JSON projection has neither gained a member nor reordered the ones
    // it has. Sorted, this assertion would hold for
    // any key order, and `receiptToJson` claims order is part of what it publishes. What pins the
    // committed twin's order is the vector-drift step of the continuous build regenerating
    // `packages/fixtures/data` and refusing a diff; this is the guard that says which order.
    const twin = receiptToJson(verified.payload, verified.cose.signature, verified.header.kid);
    expect(Object.keys(twin.payload)).toEqual([
      'v', 'iss', 'ins', 'iat', 'nce', 'req', 'res', 'mdl', 'wts', 'meas', 'att', 'epk', 'tok',
      'mk', 'sd', 'cva', 'itm',
    ]);
  });

  it('decodeReceipt reads a marked receipt by default and refuses it when narrowed', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(markedPayload(), key);

    expect(decodeReceipt(bytes).payload.mk.sch).toBe('provenance-v1');
    expectErrorCode(() => decodeReceipt(bytes, { acceptedVersions: [] }), 'UNSUPPORTED_VERSION');
    expect(decodeReceipt(bytes, { acceptedVersions: [1] }).payload.mk.sch).toBe('provenance-v1');
  });

  it('refuses to project a payload naming a version this build has no members for', () => {
    // The projection asks the same question the encoder asks, and one number wide is still a question:
    // a caller that casts has built a payload no reader of these bytes would hand back. What is asserted
    // is that the projection refuses, because the cascade the switch replaced had the old v1 shape as its
    // tail and would have answered this payload with thirteen members and a `v` rewritten to a number the
    // payload does not name.
    const unprojectable = { ...stampedPayload(), v: 4 } as unknown as ReceiptPayload;
    const refusal = expectFailure(
      () => receiptToJson(unprojectable, new Uint8Array(64).fill(3), new Uint8Array(32).fill(4)),
      'UNSUPPORTED_VERSION',
    );
    expect(refusal.message).toContain('is not projected as another version');
  });
});

/**
 * The document with its item list spelled out, so a case that wants more than one entry says how
 * many and with what instants instead of editing a shared document.
 */
function stampedWith(itm: Array<{ t: number; d: Uint8Array }>, sd: StampDisclosure = { name: 'host clock', uncertaintySeconds: null }): ReceiptPayload {
  return { ...stampedPayload(), sd, itm };
}

describe('the four members a receipt states about itself and the order of its items', () => {
  it('round-trips the three members and keeps the two readings of `unc` apart', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(stampedPayload(), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    const payload = verified.payload;

    // `null` is the source saying nobody measured and `0` is the source saying it is right, which is
    // the pair the specification's `sd` row states and the policy's own bound reads. A reader that
    // turned one into the other on the way through the codec would retire the difference the member
    // exists to carry, so this asserts the two as two documents rather than as one field.
    expect(payload.sd).toEqual({ name: 'host clock', uncertaintySeconds: null });
    expect(Object.is(payload.sd.uncertaintySeconds, null)).toBe(true);
    const measured = verifyReceipt(
      issueReceipt(stampedWith([{ t: FIXED_NOW, d: sha256(new TextEncoder().encode('{"a":1}')) }], { name: '-disc', uncertaintySeconds: 0 }), key),
      { publicKey: key.publicKey, nowSeconds: FIXED_NOW },
    );
    expect(Object.is(measured.payload.sd.uncertaintySeconds, 0)).toBe(true);
    expect(measured.payload.sd.uncertaintySeconds).not.toBeNull();

    // The anchor's two arms are the two shapes, and the item list keeps its digest as a digest.
    expect(payload.cva).toEqual({
      collateral: { presence: 'held', sha256: sha256(new TextEncoder().encode('collateral bytes')) },
      validity: { presence: 'not-taken-in', reason: 'the collector read no window' },
    });
    expect(payload.itm).toHaveLength(1);
    expect(equalBytes(payload.itm[0]!.d, sha256(new TextEncoder().encode('{"a":1}')))).toBe(true);

    // Re-encoding what the reader parsed gives back the signed bytes, which is the format's claim for
    // every version and now for the seventeen members of this one, and the projection writes the same
    // seventeen in the order `receipt.cddl` declares them, with `unc` kept as a value.
    expect(equalBytes(encodePayload(payload), verified.cose.payloadBytes)).toBe(true);
    const twin = receiptToJson(payload, verified.cose.signature, verified.header.kid);
    expect(Object.keys(twin.payload)).toEqual([
      'v', 'iss', 'ins', 'iat', 'nce', 'req', 'res', 'mdl', 'wts', 'meas', 'att', 'epk', 'tok',
      'mk', 'sd', 'cva', 'itm',
    ]);
    if (twin.payload.v !== 1) throw new Error(`the projection wrote version ${twin.payload.v} for a v1 payload`);
    expect(twin.payload.sd).toEqual({ name: 'host clock', unc: null });
    expect(twin.payload.cva).toEqual({
      col: { p: 'held', d: toHex(sha256(new TextEncoder().encode('collateral bytes'))), },
      val: { p: 'not-taken-in', r: 'the collector read no window' },
    });
    expect(twin.payload.itm).toEqual([{ t: FIXED_NOW, d: toHex(sha256(new TextEncoder().encode('{"a":1}'))) }]);
    expect(twin.payload.mk).toEqual({ sch: 'provenance-v1', d: toHex(sha256(MARKED_REGION)) });
  });

  it('refuses an absent sd, cva, itm or mk, because none of the four is a member that may be left out', () => {
    const key = generateSigningKey();
    // Each half hands the reader a document whole except for the one member, so the answer can only
    // be the absence. The sentences are quoted because each one names what the silence would read as,
    // which is the reason the member is required rather than an optional addition to v2.
    const cases: Array<[string, string]> = [
      ['sd', 'v1 requires an sd member'],
      ['cva', 'v1 requires a cva member'],
      ['itm', 'v1 requires an itm member'],
      ['mk', 'v1 requires an mk member'],
    ];
    for (const [member, sentence] of cases) {
      const bytes = signMembers(
        new Map([...membersOf(stampedPayload())].filter(([name]) => name !== member)),
        key,
      );
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(failure.message, `the payload with no ${member}`).toContain(sentence);
      expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
    }

    // One member down the same rule holds, and the absence of a bound is not the bound being zero.
    const noBound = signMembers(
      editedNested(stampedPayload(), 'sd', (nested) => { nested.delete('unc'); }),
      key,
    );
    expect(expectFailure(() => decodeReceipt(noBound)).message).toContain('sd.unc must be a non-negative integer or null');
    const noName = signMembers(
      editedNested(stampedPayload(), 'sd', (nested) => { nested.delete('name'); }),
      key,
    );
    expect(expectFailure(() => decodeReceipt(noName)).message).toContain('sd.name must be a tstr');

    // A reason is what makes an absence a state, so an absent slot with nothing beside its label is
    // the hole the specification says an anchor must not be.
    const noReason = signMembers(
      editedNested(stampedPayload(), 'cva.val', (nested) => { nested.delete('r'); }),
      key,
    );
    expect(expectFailure(() => decodeReceipt(noReason)).message).toContain('cva.val.r must be a tstr');
  });

  it('refuses a float at `sd.unc`, the one position that also takes null', () => {
    const key = generateSigningKey();
    // The integer sweep takes this position no further, because `unc` is written `int / null` and the
    // sweep reads only the positions written plain `int`. The decode reaches it the same way: a float
    // here is not the other reading of the member, and a document offering it is one this package did
    // not write. The control half on the same bytes is what says the refusal is the major type's.
    for (const [width, floated] of floatWidthsHolding(1)) {
      const bytes = signKeepingMajorTypes(
        encodeWithMajorTypes(editedNested(stampedPayload(), 'sd', (nested) => { nested.set('unc', floated); })),
        key,
        declaredProtectedHeader(key.kid),
      );
      const failure = expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
      expect(failure.message, `unc written as a ${width}`).toContain('floating point');
      expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');
    }
    const integer = signKeepingMajorTypes(
      encodeWithMajorTypes(editedNested(stampedPayload(), 'sd', (nested) => { nested.set('unc', 1); })),
      key,
      declaredProtectedHeader(key.kid),
    );
    expect(decodeReceipt(integer).payload.sd.uncertaintySeconds).toBe(1);
    // A bound written as `null` stays a `null` in the bytes rather than becoming an absent member.
    const explicit = decodeReceipt(issueReceipt(stampedPayload(), key));
    expect(membersOf(explicit.payload).get('sd')).toBeInstanceOf(Map);
    expect((membersOf(explicit.payload).get('sd') as Map<string, unknown>).get('unc')).toBeNull();
  });

  it('closes each arm of a collateral slot by the label inside it, and refuses a label it does not declare', () => {
    const key = generateSigningKey();
    // Three states, two shapes, and the shape is decided by the label rather than by which members
    // happen to be there. Each half below is a document holding one arm's claim and the other arm's
    // member, which is what a reader could not resolve without refusing it.
    const cases: Array<[string, Map<string, unknown>, string]> = [
      ['a held slot with no digest', new Map([['p', 'held']]), 'cva.col.d must be a 32-byte bstr'],
      [
        'a held slot carrying a reason',
        new Map<string, unknown>([['p', 'held'], ['r', 'both arms at once'], ['d', sha256(new Uint8Array(0))]]),
        "cva.col carries a member a held slot does not define: 'r'",
      ],
      [
        'an absent slot carrying a digest',
        new Map<string, unknown>([['p', 'not-taken-in'], ['d', sha256(new Uint8Array(0))]]),
        "cva.val carries a member an absent slot does not define: 'd'",
      ],
      [
        'a fourth presence',
        new Map<string, unknown>([['p', 'lost'], ['r', 'a label the format does not have']]),
        'cva.col.p is not one of the three presence states the format declares',
      ],
      ['a slot that is not a map', new Map([['p', 7]]), 'cva.col.p is not one of the three presence states the format declares'],
    ];
    for (const [name, slot, sentence] of cases) {
      const owner = name.startsWith('an absent') ? 'cva.val' : 'cva.col';
      const bytes = signMembers(editedNested(stampedPayload(), owner, (nested) => { nested.clear(); for (const [k, v] of slot) nested.set(k, v); }), key);
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(failure.message, name).toContain(sentence);
      expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
    }

    // The other absence is a label of its own and reads here, because the two absences are two
    // statements and a reader has to be able to tell them apart.
    const absent = { presence: 'absent-at-source', reason: 'the source had nothing to give' } as const;
    const bothAbsent = stampedWith([{ t: FIXED_NOW, d: sha256(new TextEncoder().encode('x')) }]);
    const bytes = issueReceipt({ ...bothAbsent, cva: { collateral: absent, validity: absent } }, key);
    expect(verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }).payload.cva.collateral).toEqual({
      presence: 'absent-at-source',
      reason: 'the source had nothing to give',
    });
  });

  it('refuses an item list that holds nothing, and one that is not a list', () => {
    const key = generateSigningKey();
    // A run of nothing states nothing and makes the walk over it vacuous, which is the reason the
    // pack's own item list gives for the same rule. The half below that answers with a refusal is the
    // format holding the line; the half below that accepts one entry is the line not being widened
    // past what it says.
    const empty = membersOf(stampedPayload());
    empty.set('itm', []);
    const emptyBytes = signMembers(empty, key);
    expect(expectFailure(() => decodeReceipt(emptyBytes)).message).toContain('itm declares at least one item and carries none');
    expectFailure(() => verifyReceipt(emptyBytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');

    const members = membersOf(stampedPayload());
    members.set('itm', new Map<string, unknown>([['t', FIXED_NOW]]));
    const notAList = signMembers(members, key);
    expect(expectFailure(() => decodeReceipt(notAList)).message).toContain('itm must be an array');

    const noDigest = signMembers(
      editedNested(stampedPayload(), 'itm', (nested) => { nested.delete('d'); }),
      key,
    );
    expect(expectFailure(() => decodeReceipt(noDigest)).message).toContain('itm[0].d must be a 32-byte bstr');
  });

  it('refuses a map the bytes did not deliver as a map, at each position one sits in', () => {
    const key = generateSigningKey();
    // Five positions, one table. `mk` and `meas` already answer this way for the versions that carry
    // them, and the four members a receipt states about itself add five more places where the format names a map: the two disclosures at the
    // payload, the two arms of the anchor below `cva`, and one element of the item list. Each is the
    // reader's own refusal rather than the closure walk's, because a walk over a map's members has no
    // map to enter when the value is not one, and the detail is the assertion because `BAD_PAYLOAD`
    // is what every one of these answers with: a case that checked only the code would stay green
    // whichever position the reader named, and the naming is the whole of what tells a reader which
    // member the bytes got wrong.
    const cases: Array<[string, (members: Map<string, unknown>) => void, string]> = [
      ['sd', (members) => members.set('sd', 'host clock'), 'sd must be a map'],
      ['cva', (members) => members.set('cva', 'nothing was taken in'), 'cva must be a map'],
      ['cva.col', (members) => (members.get('cva') as Map<string, unknown>).set('col', 'held'), 'cva.col must be a map'],
      ['cva.val', (members) => (members.get('cva') as Map<string, unknown>).set('val', 7), 'cva.val must be a map'],
      ['an itm element', (members) => members.set('itm', ['a frame, but not a map']), 'itm[0] must be a map'],
    ];
    for (const [where, edit, sentence] of cases) {
      const members = membersOf(stampedPayload());
      edit(members);
      const bytes = signMembers(members, key);
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(failure.message, `a ${where} that is not a map`).toContain(sentence);
      expect(expectFailure(() => decodeReceipt(bytes)).message, `the same bytes read without a key`).toContain(sentence);
    }
  });

  it('refuses a negative instant or bound where the format names a non-negative one', () => {
    const key = generateSigningKey();
    // Two positions, one table. Both take an integer the CDDL writes as non-negative, and both are
    // refused by the reader that gets there before any comparison of one stamp against another: a
    // negative bound is not a bound a reader can weigh, and a negative item instant is a frame stamped
    // before the epoch. The sentence is the assertion again, because
    // `BAD_PAYLOAD` is what every integer position in this payload answers with when the value is
    // below zero, and the code says nothing about which one moved.
    const cases: Array<[string, (members: Map<string, unknown>) => void, string]> = [
      [
        'sd.unc',
        (members) => (members.get('sd') as Map<string, unknown>).set('unc', -1),
        'sd.unc must be a non-negative integer or null',
      ],
      [
        'itm.t',
        (members) =>
          members.set('itm', [new Map<string, unknown>([['t', -1], ['d', sha256(new TextEncoder().encode('one frame'))]])]),
        'itm[0].t must be a non-negative integer',
      ],
    ];
    for (const [where, edit, sentence] of cases) {
      const members = membersOf(stampedPayload());
      edit(members);
      const bytes = signMembers(members, key);
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(failure.message, `a negative ${where}`).toContain(sentence);
      expect(expectFailure(() => decodeReceipt(bytes)).message, `the same bytes read without a key`).toContain(sentence);
    }
  });

  it('accepts items stamped in one second, which is the width of the stamp', () => {
    const key = generateSigningKey();
    // Stamps are whole seconds and two frames of one completion fall inside a second routinely, so a
    // reader that asked for strictly increasing instants would refuse ordinary traffic. The case the
    // next test takes is the same list with one instant one second lower, which is a disagreement.
    const same = FIXED_NOW;
    const bytes = issueReceipt(
      stampedWith([
        { t: same, d: sha256(new TextEncoder().encode('a')) },
        { t: same, d: sha256(new TextEncoder().encode('b')) },
        { t: same, d: sha256(new TextEncoder().encode('c')) },
      ]),
      key,
    );
    expect(verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }).payload.itm).toHaveLength(3);
    expect(decodeReceipt(bytes).payload.itm[2]!.t).toBe(same);

    const rising = issueReceipt(
      stampedWith([
        { t: same, d: sha256(new TextEncoder().encode('a')) },
        { t: same, d: sha256(new TextEncoder().encode('b')) },
        { t: same + 7, d: sha256(new TextEncoder().encode('c')) },
      ]),
      key,
    );
    expect(decodeReceipt(rising).payload.itm[2]!.t).toBe(same + 7);
  });

  it('refuses a list whose stamps disagree with the order the array states, at the payload read', () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const falling = stampedWith([
      { t: FIXED_NOW, d: sha256(new TextEncoder().encode('a')) },
      { t: FIXED_NOW, d: sha256(new TextEncoder().encode('b')) },
      { t: FIXED_NOW - 1, d: sha256(new TextEncoder().encode('c')) },
    ]);
    const bytes = issueReceipt(falling, key);

    // Its own code, and not the payload's: every member here is well-typed and in the position the
    // version puts it, and what cannot both stand is the pair of signed statements. The two positions
    // and both instants are in the sentence, because a caller reading a log has to know which pair of
    // one response contradicts itself.
    const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'ITEM_STAMP_OUT_OF_ORDER');
    expect(failure.message).toContain('itm[2] is stamped');
    expect(failure.message).toContain('itm[1] is stamped');
    expectFailure(() => decodeReceipt(bytes), 'ITEM_STAMP_OUT_OF_ORDER');

    // The reach of the check is stated as far as it goes, and no further. `decodeReceipt` consults no
    // key at all and answers with the order, which is what makes the refusal a fact of the document
    // rather than of who signed it. `verifyReceipt` runs its signature check before it parses a
    // payload, so the same bytes carrying another key's signature answer `INVALID_SIGNATURE` and never
    // reach the pair: the standing rule that an unauthenticated document gets no payload answer from
    // this package holds here as it holds for every other member. A case that claimed the order code
    // refused a forged signature too would be a claim about a capability this reader does not have.
    const forged = signWithHeaders(encodePayload(falling), other, declaredProtectedHeader(key.kid));
    expectErrorCode(() => verifyReceipt(forged, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'INVALID_SIGNATURE');
    expectErrorCode(() => decodeReceipt(forged), 'ITEM_STAMP_OUT_OF_ORDER');

    // And a narrowing that stops short of this version is a version answer, not an order one: a
    // caller that reads no version at all never reaches the pair to compare.
    expectErrorCode(() => decodeReceipt(bytes, { acceptedVersions: [] }), 'UNSUPPORTED_VERSION');
  });

  it('refuses a member the format does not define at the payload level, whichever document carries it', () => {
    const key = generateSigningKey();
    // The closed map is one rule stated one way, so the name that crosses no boundary is the one it
    // answers: a document carrying a name this format never defines is refused rather than read with
    // the member dropped, which is the silence the closed map exists to refuse. Three documents,
    // because the refusal must not depend on which of the four members about itself a payload states.
    const cases: Array<[ReceiptPayload, string, string]> = [
      [samplePayload(), 'surprise', "payload carries a member version 1 does not define: 'surprise'"],
      [markedPayload(), 'not_a_member', "payload carries a member version 1 does not define: 'not_a_member'"],
      [stampedPayload(), 'enc', "payload carries a member version 1 does not define: 'enc'"],
    ];
    for (const [payload, member, sentence] of cases) {
      const members = membersOf(payload);
      members.set(member, 'x');
      const bytes = signMembers(members, key);
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(failure.message, `${member} on the payload`).toContain(sentence);
      expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
    }
  });
});

/**
 * The members of a payload, with `edit` applied inside the map the format puts at `route`. The maps
 * below the payload are what the closedness rule reaches, and every case here has to be a document
 * that is whole except for what the edit wrote. `membersOf` builds fresh nested maps on every call, so
 * an edit cannot leak from one case into the next.
 *
 * The route is dotted where a map sits behind another map's member, and a step that lands on a list
 * takes its first element: the member the format writes as an array of maps is closed at the element,
 * so a closure rule that stopped at the list rather than reaching inside it would refuse nothing at
 * all, and an edit that stopped at the list would edit nothing.
 */
function editedNested(
  payload: ReceiptPayload,
  route: string,
  edit: (nested: Map<unknown, unknown>) => void,
): Map<string, unknown> {
  const members = membersOf(payload);
  let cursor: unknown = members;
  for (const part of route.split('.')) {
    if (Array.isArray(cursor)) cursor = cursor[0];
    if (!(cursor instanceof Map)) throw new Error(`the corpus carries no ${route} map to edit`);
    cursor = cursor.get(part);
  }
  if (Array.isArray(cursor)) cursor = cursor[0];
  if (!(cursor instanceof Map)) throw new Error(`the corpus carries no ${route} map to edit`);
  edit(cursor);
  return members;
}

/** A document of the payload version the closure walk names, which is the whole corpus here. */
function payloadForVersion(version: string): ReceiptPayload {
  if (version === '1') return stampedPayload();
  throw new Error(`this corpus has no document for payload version ${version}`);
}

/**
 * The document a swept or edited position belongs to. A position the format names is a position this one
 * document carries; a member it names nowhere is not, and rewriting one on a document that holds no such
 * member would edit nothing and then assert a refusal those bytes never invited. Read off the versions the
 * walk defines rather than switched on by name, so a position the format gains arrives in the sweep on the
 * day the CDDL declares it.
 */
function payloadCarrying(route: string): ReceiptPayload {
  const head = route.split('.')[0]!;
  for (const version of Object.keys(receiptParser.DEFINED_MAPS)) {
    const payload = payloadForVersion(version);
    if (membersOf(payload).has(head)) return payload;
  }
  throw new Error(`no version of this corpus carries a ${head} member`);
}

/**
 * One closedness case: the document carrying the map, the route to it through the bytes, and the
 * position the reader names when it refuses a member sitting inside that map. Route and position
 * differ exactly where the route reaches inside a list, which is where a walk over member names
 * cannot go and the element's own reader can.
 */
interface ClosureCase {
  readonly payload: ReceiptPayload;
  readonly route: string;
  readonly position: string;
}

/**
 * The maps a payload version reaches that the closure walk cannot enter by member name, read out of
 * the block that declares them: a member bound to a rule through an array (`itm` today) is closed at
 * its element, and a member whose rule names members that are rules of their own (`cva.col` and
 * `cva.val`, the two arms the label inside a slot selects) is closed one level below the map the walk
 * enters. Neither kind is written out here, and neither is asked of the walk's own `nested`, because a
 * hand-written list of positions is the copy that stays green the day the format gains a third map of
 * this shape and nothing starts refusing at it.
 */
function casesBeyondTheWalk(cddl: string, version: number, payload: ReceiptPayload): ClosureCase[] {
  const rules = nestedRuleNames(cddl);
  const cases: ClosureCase[] = [];
  for (const member of memberDeclarations(cddlRule(cddl, `Ashaveri-Receipt-Payload-v${version}`))) {
    const rule = rules.get(member.name);
    if (rule === undefined) continue;
    if (member.type.startsWith('[+')) {
      cases.push({ payload, route: member.name, position: positionOf(member.name) });
      continue;
    }
    for (const arm of cddlRuleArms(cddl, rule)) {
      for (const inner of memberDeclarations(arm)) {
        if (/^[A-Z]/u.test(inner.type)) cases.push({ payload, route: `${member.name}.${inner.name}`, position: `${member.name}.${inner.name}` });
      }
    }
  }
  return cases;
}

/**
 * One case per map per version, read off the structure the walk enforces and off the blocks the CDDL
 * declares, rather than spelled out here. The schema test derives the twin's matrices from the same
 * two sources, so a map the format gains arrives in each of them on the day it lands and a version
 * with no document here fails the run rather than covering one case fewer.
 */
function nestedCases(): ClosureCase[] {
  const cddl = readCddl();
  return Object.entries(receiptParser.DEFINED_MAPS).flatMap(
    ([version, defined]): ClosureCase[] => {
      const payload = payloadForVersion(version);
      const walked = Object.keys(defined.nested ?? []).map(
        (key): ClosureCase => ({ payload, route: key, position: key }),
      );
      return [...walked, ...casesBeyondTheWalk(cddl, Number(version), payload)];
    },
  );
}

describe('the payload map and every map nested inside it are closed', () => {
  it('refuses an undefined member inside meas, att, tok and mk, and names the one it refused', () => {
    const key = generateSigningKey();
    // Both halves of every case below: the unedited document verifies, so a refusal is the added
    // member's answer and not one this corpus was already failing for.
    for (const version of Object.keys(receiptParser.DEFINED_MAPS)) {
      const unedited = issueReceipt(payloadForVersion(version), key);
      expect(() => verifyReceipt(unedited, { publicKey: key.publicKey, nowSeconds: FIXED_NOW })).not.toThrow();
    }

    // Two halves of the sentence are matched, and each is a fact of its own: the position says the
    // reader reached the map it was told to close, and the name says it refused the member it found
    // rather than the document it was handed. Which phrase names the definer between them is the
    // reader's prose about which shape it read the map as, and the two spellings it uses are pinned
    // word for word by the cases further down this file.
    for (const one of nestedCases()) {
      const bytes = signMembers(editedNested(one.payload, one.route, (nested) => nested.set('surprise', 'x')), key);
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(
        failure.message,
        `a v${one.payload.v} payload with an undefined member inside ${one.route}`,
      ).toContain(`${one.position} carries a member`);
      expect(failure.message, `the member refused inside ${one.route}`).toContain(`does not define: 'surprise'`);
      // The same answer with no signature check to reach it through: closedness is a fact about the
      // payload rather than about who signed it, so an unread document is refused as a verified one is.
      expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
    }

    // A key that is not a text label is not a member at either level, and it is named the way the
    // payload level names one, because nothing about it became a text label by sitting deeper.
    const foreignKey = signMembers(
      editedNested(samplePayload(), 'tok', (nested) => nested.set(new Uint8Array([7]), 'x')),
      key,
    );
    const refusal = expectFailure(() => verifyReceipt(foreignKey, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
    expect(refusal.message).toContain('tok carries a member the format does not define: a bstr key of length 1');
  });

  it('leaves the refusals that came before it answer first', () => {
    const key = generateSigningKey();
    // A `p` that is a string is a member the format does define holding a value it does not, so the
    // walk has nothing to refuse and the reader's own sentence is what a caller hears. The code is
    // `BAD_PAYLOAD` either way, which is exactly why the detail is the assertion: a walk that checked
    // values as well as names would answer this document with a membership refusal, and only the
    // message would say that the check had swallowed the one this format has always made here.
    const stringPrompt = editedNested(markedPayload(), 'tok', (nested) => nested.set('p', 'twelve'));
    const misTyped = expectFailure(() => verifyReceipt(signMembers(stringPrompt, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
    expect(misTyped.message).toContain('tok.p must be a non-negative integer');

    // A member the format makes a map and the bytes did not deliver one is still the reader's answer,
    // because the walk has no map to enter and cannot claim a membership failure it cannot see.
    const measIsText = membersOf(samplePayload());
    measIsText.set('meas', 'snp');
    const meas = expectFailure(() => verifyReceipt(signMembers(measIsText, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
    expect(meas.message).toContain('meas must be a map');

    const mkIsText = membersOf(markedPayload());
    mkIsText.set('mk', 'none');
    const mark = expectFailure(() => verifyReceipt(signMembers(mkIsText, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
    expect(mark.message).toContain('mk must be a map');
  });
});

/**
 * A copy of one of the corpus payloads with one member added to one of the maps it nests, at the
 * position the reader's own refusal names. `structuredClone` rather than a spread because the payloads
 * carry byte strings the tests compare by identity elsewhere, and a poisoned document that shares a
 * `Uint8Array` with the clean one would make the two cases harder to tell apart than they already are.
 */
function givenWithMember(payload: ReceiptPayload, position: string, name: string, value: unknown): ReceiptPayload {
  const copy = structuredClone(payload) as unknown as ReceiptPayload;
  const root = copy as unknown as Record<string, unknown>;
  let holder: Record<string, unknown> | undefined;
  if (position === 'payload') {
    holder = root;
  } else if (position === 'itm[0]') {
    holder = (root['itm'] as Record<string, unknown>[])[0];
  } else if (position === 'cva.col' || position === 'cva.val') {
    // The two arms of the anchor, whose wire names the interface spells out: the position is the one
    // the reader refuses at and the key is the one a caller hands that arm under.
    holder = (root['cva'] as Record<string, unknown>)[position === 'cva.col' ? 'collateral' : 'validity'] as Record<string, unknown>;
  } else {
    holder = root[position] as Record<string, unknown> | undefined;
  }
  if (holder === undefined || holder === null || typeof holder !== 'object') {
    throw new Error(`this corpus carries no ${position} map to poison`);
  }
  holder[name] = value;
  return copy;
}

/** The same document with one of its own members taken away, which is the state no type can express. */
function givenWithoutMember(payload: ReceiptPayload, name: string): ReceiptPayload {
  const copy = { ...(payload as unknown as Record<string, unknown>) };
  delete copy[name];
  return copy as unknown as ReceiptPayload;
}

describe('what the writer refuses to make, and what it makes anyway', () => {
  it('refuses a member the format does not define, and names the member and the version it read', () => {
    // The writer answers with the reader's sentence and the reader's code, so the names it refuses are
    // the ones no block of this format defines. `enc` is a name an outside implementation might hand
    // over for an encryption marker, and the four members a receipt states about itself are the ones a
    // caller is most likely to move: each is spelled here as an extra one, because a writer that trimmed
    // in silence is the defect this walk was placed in front of.
    const cases: Array<[string, ReceiptPayload]> = [
      ['surprise', givenWithMember(samplePayload(), 'payload', 'surprise', 'x')],
      ['enc', givenWithMember(markedPayload(), 'payload', 'enc', { alg: 'none' })],
      ['extra', givenWithMember(stampedPayload(), 'payload', 'extra', [{ t: FIXED_NOW, d: sha256(new TextEncoder().encode('x')) }])],
    ];
    for (const [member, payload] of cases) {
      const failure = expectFailure(() => encodePayload(payload));
      expect(failure.message, `the payload carrying ${member}`).toContain(
        `payload carries a member version 1 does not define: '${member}'`,
      );
    }

    // The refusal is the whole of the answer: no bytes come back for a caller to sign, so the
    // silent-drop path has nothing left to be silent about. `issueReceipt` is the honest caller's path
    // and it answers alike, before a key is consulted.
    const key = generateSigningKey();
    expect(() => encodePayload(cases[0]![1])).toThrow(ReceiptError);
    expectFailure(() => issueReceipt(cases[0]![1], key), 'BAD_PAYLOAD');
  });

  it('refuses a required member the payload does not carry, one at a time, for the version the format declares', () => {
    // A `TypeError` is not a refusal, and a test that quoted its message would be worth nothing: what
    // this file proves is the code. `expectFailure` reads `code` off the object it was handed, so a
    // plain `TypeError` arriving here reports `undefined` and the cell goes red rather than green on a
    // crash. The member list is read off `DEFINED_MAPS`, the structure the reader's closedness walk
    // walks, so a member a later version adds arrives in this sweep on the day it is defined and is
    // never a list this file has to be told about twice.
    for (const [version, defined] of Object.entries(receiptParser.DEFINED_MAPS)) {
      const payload = payloadForVersion(version);
      for (const member of defined.members) {
        if (member === 'v') continue;
        const failure = expectFailure(() => encodePayload(givenWithoutMember(payload, member)));
        expect(failure.message, `v${version} with no ${member}`).toContain(
          `payload is missing '${member}', which version ${version} requires`,
        );
      }
    }

    // `v` is answered by the version check that runs before a member list is read, in the reader's own
    // sentence, because a document naming no version says nothing about which version's list it is
    // short of. Naming `v` as a missing member would be the encoder guessing a version for it.
    const noVersion = expectFailure(() => encodePayload(givenWithoutMember(stampedPayload(), 'v')));
    expect(noVersion.message).toContain('v must be an integer receipt version');
    expectFailure(() => encodePayload({ ...stampedPayload(), v: '3' as never }), 'BAD_PAYLOAD');

    // One member down, the same two answers hold, and the map the format writes is refused as a map
    // rather than reached for a member it does not have.
    const noBound = expectFailure(() => encodePayload(givenWithMember(stampedPayload(), 'sd', 'uncertaintySeconds', undefined)));
    expect(noBound.message).toContain("sd is missing 'uncertaintySeconds', which the format requires");
    const noDigest = expectFailure(() => encodePayload(givenWithoutMember(stampedPayload(), 'mk')));
    expect(noDigest.message).toContain("payload is missing 'mk', which version 1 requires");
    const slotIsText = expectFailure(() =>
      encodePayload({ ...stampedPayload(), cva: { collateral: 'held', validity: stampedPayload().cva.validity } as never }),
    );
    expect(slotIsText.message).toContain('cva.col is not a map the format writes');
  });

  it('refuses a member the format does not define inside every map a version nests', () => {
    // One case per map per version, from the same derived list the reader's closedness sweep walks, so
    // the two directions are held to one set of positions. The name is the one the reader's own rows
    // carry, and the position in the message is the one a caller would have to work out from the bytes.
    for (const one of nestedCases()) {
      const failure = expectFailure(() => encodePayload(givenWithMember(one.payload, one.position, 'surprise', 1)));
      expect(failure.message, `the member refused inside ${one.position}`).toContain(`does not define: 'surprise'`);
      expect(failure.message, `the position named for ${one.position}`).toContain(`${one.position} carries a member`);
    }
  });

  it('refuses a collateral slot carrying the other arm, and one missing its own', () => {
    // Which list stands behind a slot is the label inside it's answer, exactly as on the read side, so
    // a slot holding both claims is refused for the member its own arm does not name rather than for
    // the pair of statements it is. A held slot with no digest is the same document one member short.
    const both = { presence: 'held', sha256: sha256(new TextEncoder().encode('bytes')), reason: 'and a reason' };
    const heldWithReason = expectFailure(() =>
      encodePayload({ ...stampedPayload(), cva: { collateral: both, validity: stampedPayload().cva.validity } as never }),
    );
    expect(heldWithReason.message).toContain("cva.col carries a member a held slot does not define: 'reason'");

    const absentWithDigest = expectFailure(() =>
      encodePayload({
        ...stampedPayload(),
        cva: { collateral: { presence: 'absent-at-source', reason: 'gone', sha256: new Uint8Array(32) } as never, validity: stampedPayload().cva.validity },
      }),
    );
    expect(absentWithDigest.message).toContain("cva.col carries a member an absent slot does not define: 'sha256'");

    const noReason = expectFailure(() =>
      encodePayload({
        ...stampedPayload(),
        cva: { collateral: { presence: 'absent-at-source' } as never, validity: stampedPayload().cva.validity },
      }),
    );
    expect(noReason.message).toContain("cva.col is missing 'reason', which an absent slot requires");

    // A label outside the three presence states names no arm, so nothing about the slot's members can
    // be settled and the refusal says the label instead, as the reader's own slot check does.
    const foreign = expectFailure(() =>
      encodePayload({
        ...stampedPayload(),
        cva: { collateral: { presence: 'elsewhere', reason: 'x' } as never, validity: stampedPayload().cva.validity },
      }),
    );
    expect(foreign.message).toContain('cva.col.p is not one of the three presence states the format declares');
  });

  it('answers the version before it answers the members, and the payload before it answers a version', () => {
    // A caller that casts reaches the encoder with a document no arm of this file writes. The version is
    // the first question, so a payload that is short three members and names a version nobody declared
    // is refused for the version and not for the members: which of the two a caller hears first is the
    // difference between "this format does not exist here" and "your document is incomplete", and the
    // reader settles them in this order too.
    const foreign = expectFailure(
      () => encodePayload({ v: 4, iss: 'a' } as unknown as ReceiptPayload),
      'UNSUPPORTED_VERSION',
    );
    expect(foreign.message).toContain('a payload naming a version this encoder has no members for');

    // Nothing at all handed over is not a payload short a member either. A property read on `null` is
    // the uncoded crash this walk replaces, so the refusal is named and its code is the payload's.
    for (const nothing of [null, undefined, 'payload', 7, []]) {
      expectFailure(() => encodePayload(nothing as unknown as ReceiptPayload), 'BAD_PAYLOAD');
    }
    expect(expectFailure(() => encodePayload(null as unknown as ReceiptPayload)).message).toContain(
      'payload is not a map the format writes',
    );
  });

  it('writes the list it was handed even where the format will not read it back', () => {
    // Fidelity is the writer's rule and legality is the reader's, and the line matters: this document is
    // a published vector, made by `issueReceipt` over an empty `itm`, and a writer that decided legality
    // could not publish a refusal for a state it can still spell. So the empty list is written, the
    // bytes say `itm` holds nothing, and the reader is the one that refuses it.
    const empty = { ...stampedPayload(), itm: [] };
    const bytes = encodePayload(empty);
    const expected = new Map<string, unknown>([...membersOf(stampedPayload())]);
    expected.set('itm', []);
    expect(equalBytes(bytes, encodeCanonical(expected))).toBe(true);

    // And the refusal is the reader's, on the writer's own bytes, signed or not.
    const key = generateSigningKey();
    const signed = issueReceipt(empty, key);
    expectFailure(() => decodeReceipt(signed), 'BAD_PAYLOAD');
    expect(expectFailure(() => decodeReceipt(signed)).message).toContain('itm declares at least one item and carries none');

    // A value the format types and does not define is the same division: `encodePayload` writes the
    // label it was handed, and `decodeReceipt` is the one that says it knows no such environment kind.
    const foreignKind = samplePayload({ meas: { tee: 'snp+h100cc' as never, m: new Uint8Array(48).fill(7) } });
    const written = encodePayload(foreignKind);
    const foreign = new Map<string, unknown>([...membersOf(samplePayload())]);
    foreign.set('meas', new Map<string, unknown>([['tee', 'snp+h100cc'], ['m', new Uint8Array(48).fill(7)]]));
    expect(equalBytes(written, encodeCanonical(foreign))).toBe(true);
    expectFailure(() => decodeReceipt(signCoseSign1(written, key)), 'BAD_PAYLOAD');

    // Two items out of order are the last pair: every member is present, named and typed, and what
    // disagrees is a pair of signed statements, which is a reader's finding, not a projection failure.
    const falling: ReceiptPayload = { ...stampedPayload(), itm: [{ t: FIXED_NOW, d: sha256(new TextEncoder().encode('a')) }, { t: FIXED_NOW - 1, d: sha256(new TextEncoder().encode('b')) }] };
    expect(equalBytes(encodePayload(falling), encodeCanonical(membersOf(falling)))).toBe(true);
    expectFailure(() => decodeReceipt(issueReceipt(falling, key)), 'ITEM_STAMP_OUT_OF_ORDER');
  });

  it('writes every well-formed document exactly as the format lays its members out', () => {
    // The accepted shapes, for their bytes rather than for a code: one spelling of the layout is this
    // package's projection and the other is `membersOf`, written out beside the CDDL order in this file,
    // and the two agreeing is what it means for nothing to have been dropped, added or reordered.
    for (const payload of [samplePayload(), markedPayload(), stampedPayload()]) {
      expect(equalBytes(encodePayload(payload), encodeCanonical(membersOf(payload))), `v${payload.v} projection`).toBe(true);
    }

    // And the round trip, which is the format's own claim and the one a published byte rests on: the
    // bytes a signature covers are the bytes the reader hands back to the writer.
    const key = generateSigningKey();
    for (const payload of [samplePayload(), markedPayload(), stampedPayload()]) {
      const verified = verifyReceipt(issueReceipt(payload, key), { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
      expect(equalBytes(encodePayload(verified.payload), verified.cose.payloadBytes), `v${payload.v} re-encode`).toBe(true);
    }

    // What the walk reads is the structure the reader reads: `SLOT_INPUT_MEMBERS` in `receipt.ts` is
    // one name per member of the two wire lists the arms are spelled from, and a fourth member added
    // to either without the writer's table knowing is the disagreement this holds loud. It is the same
    // argument the writer's own comment makes about the slot lists being written out rather than derived.
    for (const [wire, input] of [
      [receiptParser.COLLATERAL_HELD_MEMBERS, ['presence', 'sha256']],
      [receiptParser.COLLATERAL_ABSENT_MEMBERS, ['presence', 'reason']],
    ] as const) {
      expect(input.length, `the slot arm lists carry one name per wire member of ${wire.join('+')}`).toBe(wire.length);
    }
  });

  it('holds the writer\'s attested text class to every text member the format declares', () => {
    // Both halves of one question, asked of two sources that cannot see each other: what `receipt.cddl`
    // types as a `tstr`, read out of the CDDL, and what `assertAttestedText` refuses, read out of the
    // writer's own table. A text member arriving in the format and not in the table is a position no
    // refusal reaches, and a table entry naming nothing in the format is a refusal of a member that does
    // not exist; either disagreement is this cell, and neither direction is quiet.
    //
    // The roster is spelled out beside the two readings rather than left to their agreement, because it is
    // the record of what the format declares at this head: seven member names across eight positions, the
    // two legs of the anchor carrying one name. A change to it is a change to what a payload may hold, and
    // it is supposed to be loud here before it is anywhere else.
    const declared = cddlTextPositions(readCddl());
    expect([...declared].sort(), 'the text positions receipt.cddl declares').toEqual([
      'att.url',
      'cva.col.r',
      'cva.val.r',
      'ins',
      'iss',
      'mdl',
      'mk.sch',
      'sd.name',
    ]);
    expect(attestedTextPositions().map((one) => one.position), 'every position the writer refuses at').toEqual(declared);
    expect(new Set(declared.map((one) => one.split('.').pop())).size, 'distinct member names in the class').toBe(7);

    // The sets this rule deliberately does not reach, stated because a reader of the derivation will ask:
    // `tee` and `p` are closed choices between literals, `v` is an integer literal, and no other position
    // in the file is a text member. The two slot arms contribute their one reason member and nothing else.
    expect(declared.filter((one) => one.endsWith('.p') || one.endsWith('.tee'))).toEqual([]);
  });

  it('refuses at the writer every attested text member that could forge a line, and names the one it stopped on', () => {
    // One refusal per member per defect class, on the document that member's version carries. The classes
    // are the four the rule answers: a character that ends a line, a format character that hides one or
    // reorders it, the astral tag block, and an extent nothing quotes. What each is refused for is the same
    // fact about all of them, which is that the printed row stops being the row the bytes say they are.
    for (const one of attestedTextPositions()) {
      for (const defect of LINE_DEFECTS) {
        const failure = expectFailure(() => encodePayload(withTextAt(one, defect.text)));
        expect(failure.message, `${one.position} carrying ${defect.name}`).toContain(`${one.position} `);
        expect(failure.message, `${one.position} refused for ${defect.name}`).toContain(defect.expect);
      }
    }

    // The refusal names the position rather than the whole document, which is the difference between a
    // caller finding a value and a caller guessing which of seven members it put there.
    const which = expectFailure(() => encodePayload(withTextAt(thePosition('cva.val.r'), 'gone\n')));
    expect(which.message).toContain('cva.val.r carries the code point a');
    expect(which.message).not.toContain('cva.col');
  });

  it('refuses to seal any of them, on the path that makes a record rather than the one that assembles a payload', () => {
    // `issueReceipt` is the call `gateway/src/server.ts` makes with a payload it built out of its own
    // configuration and its declared roster, so this is the writer's refusal met where a record is made.
    // A refusal that only reached a hand-built payload would leave a gateway that assembled the document
    // first and signed it anyway, and no bytes are the answer this unit is for.
    const key = generateSigningKey();
    for (const one of attestedTextPositions()) {
      const payload = withTextAt(one, 'a\nb');
      expectFailure(() => issueReceipt(payload, key), 'BAD_PAYLOAD');
    }

    // And the same document one character away from the refusal does seal, so the cells above are about
    // the character and not about the member being text at all.
    const sealed = issueReceipt(withTextAt(thePosition('cva.val.r'), 'gone'), key);
    expect(readTextAt(decodeReceipt(sealed).payload, thePosition('cva.val.r'))).toBe('gone');
  });

  it('accepts the text a line is made of at every attested member, and writes it exactly as it was handed', () => {
    // The clean half of the class. First what this corpus already publishes: nothing about a document that
    // passed before this rule existed moves, so the bytes a signature covers stay the bytes the layout says
    // they are, member for member and in the order the format lists them.
    for (const payload of [samplePayload(), markedPayload(), stampedPayload()]) {
      expect(equalBytes(encodePayload(payload), encodeCanonical(membersOf(payload))), `v${payload.v} clean class`).toBe(true);
    }

    // Then the shapes a real value of this class carries that a narrower rule would have refused: an inner
    // space, text outside ASCII, a symbol above the BMP, an ideograph, a run no ceiling here bounds, and the
    // one scheme label the CDDL spells as a literal. The writer takes each of them at every position of the
    // class and writes it into the bytes the format lays out, which is the whole of what this rule claims.
    for (const one of attestedTextPositions()) {
      for (const text of ADMITTED_TEXTS) {
        const payload = withTextAt(one, text);
        expect(
          equalBytes(encodePayload(payload), encodeCanonical(membersOf(payload))),
          `${one.position} carrying ${JSON.stringify(text.slice(0, 24))}`,
        ).toBe(true);
      }
    }

    // And each one seals and reads back as the same string, which is the half a byte comparison cannot give:
    // the position is a `tstr` on the wire and the caller's own text in the hand of a verifier. `mk.sch` is
    // the one position a reader bounds further than this writer does, and under its own code: the marking
    // registry is a closed set the format declares, while the rule here is about the line a value prints on,
    // so an unregistered but line-safe label is signed and then refused on the way back.
    const key = generateSigningKey();
    for (const one of attestedTextPositions()) {
      for (const text of one.position === 'mk.sch' ? REGISTERED_SCHEMES : ADMITTED_TEXTS) {
        const decoded = decodeReceipt(issueReceipt(withTextAt(one, text), key));
        expect(readTextAt(decoded.payload, one), `${one.position} carrying ${JSON.stringify(text.slice(0, 24))}`).toBe(text);
      }
    }
    const unregistered = withTextAt(thePosition('mk.sch'), 'not-a-scheme-in-the-registry');
    expect(() => encodePayload(unregistered)).not.toThrow();
    expectFailure(() => decodeReceipt(issueReceipt(unregistered, key)), 'UNSUPPORTED_SCHEME');
  });
});

/**
 * The values a clean member of the class may hold, none of them a refusal: they are here to show that what
 * this rule reaches is characters a line is made of, and not a set of allowed spellings, an alphabet, or a
 * length. `'none'` is the label `receipt.cddl` names as a literal beside the open alternative.
 */
const ADMITTED_TEXTS = [
  'meta-llama/Llama-3.1-8B-Instruct',
  'ptp-disciplined host clock',
  'ünïcødé label with ãccents',
  'a symbol ✓ and a CJK 漢字 run',
  'x'.repeat(4_096),
  'none',
];

/** The marking labels this package's reader interprets, for the position it bounds past the writer. */
const REGISTERED_SCHEMES = ['none', 'provenance-v1'];

/**
 * Every attested text position, named the way a refusal names it and reachable through the input names a
 * caller hands the value under. Read off the writer's own table rather than typed out again beside it, so
 * the sweep over the class is asked about a position the day the class gains one.
 */
function attestedTextPositions(): Array<{ position: string; path: readonly string[] }> {
  return receiptParser.ATTESTED_TEXT_ROWS.flatMap((row) =>
    row.positions.map((one) => ({
      position: row.position === '' ? one.wire : `${row.position}.${one.wire}`,
      path: [...row.path, one.input],
    })),
  );
}

/** One position of the class by the name a refusal gives it, so no case spells the path out a second time. */
function thePosition(position: string): { position: string; path: readonly string[] } {
  const found = attestedTextPositions().find((one) => one.position === position);
  if (found === undefined) throw new Error(`the writer's class carries no ${position}`);
  return found;
}

/**
 * The same document with one attested text member carrying the value a case names.
 *
 * A leg of the anchor is swept at the arm that carries its text member: the corpus holds a held collateral,
 * and `r` belongs to an absent one, so a case that only wrote the reason would be refused for a member the
 * arm its own label selects does not define. Moving the label therefore moves the digest with it, which is
 * the pair the format states: an absent slot carries a reason and no digest, and a held one the reverse.
 */
function withTextAt(one: { position: string; path: readonly string[] }, value: string): ReceiptPayload {
  const copy = structuredClone(payloadCarrying(one.position)) as unknown as ReceiptPayload;
  const root = copy as unknown as Record<string, unknown>;
  let holder: Record<string, unknown> = root;
  for (const step of one.path.slice(0, -1)) {
    holder = holder[step] as Record<string, unknown>;
    if ('presence' in holder) {
      holder['presence'] = 'not-taken-in';
      delete holder['sha256'];
    }
  }
  holder[one.path[one.path.length - 1]!] = value;
  return copy;
}

/** What a sealed document says about one attested text member, read back off the decoded payload. */
function readTextAt(payload: ReceiptPayload, one: { position: string; path: readonly string[] }): unknown {
  const root = payload as unknown as Record<string, unknown>;
  let holder: Record<string, unknown> = root;
  for (const step of one.path.slice(0, -1)) holder = holder[step] as Record<string, unknown>;
  return holder[one.path[one.path.length - 1]!];
}

/**
 * The defect classes this rule answers, each with the character it is made of and the half of the
 * refusal's sentence that names it. Every position is fed every class, so a member the scan reached by
 * accident rather than by the table has nowhere to hide.
 */
const LINE_DEFECTS: ReadonlyArray<{ name: string; text: string; expect: string }> = [
  { name: 'a line feed', text: 'a\nb', expect: 'carries the code point a,' },
  { name: 'a carriage return', text: 'a\rb', expect: 'carries the code point d,' },
  { name: 'a line separator', text: 'a\u2028b', expect: 'carries the code point 2028,' },
  { name: 'a paragraph separator', text: 'a\u2029b', expect: 'carries the code point 2029,' },
  { name: 'a C1 next line', text: 'a\u0085b', expect: 'carries the code point 85,' },
  { name: 'a soft hyphen', text: 'a\u00adb', expect: 'carries the code point ad,' },
  { name: 'a zero width space', text: 'a\u200bb', expect: 'carries the code point 200b,' },
  { name: 'a right-to-left override', text: 'a\u202eb', expect: 'carries the code point 202e,' },
  { name: 'a byte order mark', text: 'a\ufeffb', expect: 'carries the code point feff,' },
  { name: 'a tag character', text: 'a\u{e0020}b', expect: 'carries the code point e0020,' },
  { name: 'a cancelled tag', text: 'a\u{e007f}b', expect: 'carries the code point e007f,' },
  { name: 'a leading space', text: ' ab', expect: 'carries leading or trailing space' },
  { name: 'a trailing space', text: 'ab ', expect: 'carries leading or trailing space' },
];

/**
 * The bytes of a document in which every number keeps the major type it was written with. The
 * package's own canonical writer cannot produce these: `encodeCanonical` ignores a boxed number's
 * original encoding on purpose, and writes any whole number as an integer, negative zero included, so
 * that the document it issues is one this package reads. A case that wants to hand the reader a float
 * where the CDDL names an integer has to step outside that writer and use the plain one, which honours
 * the width the value carries.
 */
function encodeWithMajorTypes(value: unknown): Uint8Array {
  return new Uint8Array(encode(value, { ...defaultEncodeOptions, sortKeys: sortCoreDeterministic }));
}

/**
 * The three widths CBOR writes a floating-point number in, each carrying the same whole number as
 * the integer it stands beside. Half-precision is available for every value the cases below use,
 * which is why they are small: the pair is one value in two major types, and a unix timestamp would
 * have to be rounded before it could be written as a float at all.
 */
function floatWidthsHolding(value: number): Array<[string, unknown]> {
  return [
    ['half-precision', encodedNumber(value, 'f16')],
    ['single-precision', encodedNumber(value, 'f32')],
    ['double-precision', encodedNumber(value, 'f64')],
  ];
}

/**
 * The two bignum spellings of one value: a tag 2 around the bytes of a whole number plain enough for a
 * CBOR integer, and a tag 2 around one no `number` holds exactly. Section 3 of the specification states
 * the refusal of both at the payload's positions, so the cases below put them there: the header label
 * an earlier case reaches is a different document, and a claim about the payload is not proved beside
 * it.
 *
 * The two fail at two points, for two reasons. The value an integer could hold is refused at the
 * decode, because the encoding this format requires spells it as one; the detail a caller hears is the
 * decoder's own sentence about a bigint that need not be one. The value no `number` holds survives
 * that, because there is no shorter spelling of it, and is refused where the field is read: it arrives
 * as a `bigint`, and no position the format types as an integer takes a value of that shape.
 */
function bignumWidthsHolding(value: number): Array<[string, unknown]> {
  return [
    ['a bignum of a value an integer holds', encodedNumber(value, 'bigint')],
    ['a bignum outside the range a number holds', encodedNumber(BigInt(value) + (1n << 80n), 'bigint')],
  ];
}

/**
 * The sentence `receipt.ts` answers with at one position when the value there is not a number it can
 * read. Quoted because the two bignum halves above are refused at two different points, and which of
 * the two answered a document is the fact the case is asserting.
 */
function fieldSentence(where: string): string {
  return where === 'v' ? 'v must be an integer receipt version' : `${where} must be a non-negative integer`;
}

/**
 * A signed receipt whose protected header and unprotected map are the ones handed in, with every
 * number in them kept as written. The signature is made over those bytes, so a refusal below is a
 * reader declining a document that carries its issuer's own signature, not one it repaired first.
 */
function signKeepingMajorTypes(
  payloadBytes: Uint8Array,
  key: SigningKey,
  protectedHeader: Map<unknown, unknown>,
  unprotectedHeader: Map<unknown, unknown> = new Map(),
): Uint8Array {
  const protectedBytes = encodeWithMajorTypes(protectedHeader);
  const signature = ed25519.sign(
    encodeCanonical(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]),
    key.privateKey,
  );
  return encodeWithMajorTypes(
    new Tag(COSE_SIGN1_TAG, [protectedBytes, unprotectedHeader, payloadBytes, signature]),
  );
}

/**
 * The corpus payload with one integer position rewritten. A name with no dot in it is a member of the
 * payload itself and is set on the map; a dotted one goes through `editedNested`, which is the same
 * route the closure cases take and leaves every other member exactly as `membersOf` wrote it. The
 * branches are read off the shape of the name rather than off a list of positions, so the row a
 * position contributes below is the row that rewrites it, and the document each row rewrites is the
 * oldest version that carries the member the route starts at.
 */
function payloadWith(where: string, value: unknown): Map<string, unknown> {
  if (!where.includes('.')) {
    const members = membersOf(payloadCarrying(where));
    members.set(where, value);
    return members;
  }
  const [owner, name] = where.split('.') as [string, string];
  return editedNested(payloadCarrying(where), owner, (nested) => nested.set(name, value));
}

/**
 * What a parsed payload carries at one of those positions, read the same way the cases name them. A
 * bracketed step indexes a list, so the reader's own spelling of an element (`itm[0].t`) is the one
 * route this function understands without a second naming convention.
 */
function valueAt(payload: ReceiptPayload, where: string): unknown {
  let cursor: unknown = payload;
  for (const part of where.replace(/\[(\d+)\]/gu, '.$1').split('.')) {
    cursor = (cursor as Record<string, unknown>)[part];
  }
  return cursor;
}

/**
 * Every position the format types as an integer, with the value each case puts there: the six
 * for which `receipt.cddl` writes `int`, namely `iat`, `epk`, one below each of the maps nested
 * inside the payload and one below the element of the list it nests, and `v`, which the same file
 * types as the integer literals `1`, `2` and `3` rather than as `int`. The
 * whole roster belongs to the sweep, including the literals: a `1.0` at the version is exactly the
 * thing the rule refuses, refused before a reader ever decides which version the document claims.
 *
 * The names are read off `receipt.cddl` rather than written out here, which is also how the two
 * documents that list them are held, because a roster typed out in a test is one the format leaves
 * behind: the day a payload block gains an integer member, a hand-written list keeps the sweep at the
 * positions it happens to name and the run stays green. Only the value is chosen here, and every
 * position takes `2` but the version, whose accepted values are a set rather than a range. `2` is
 * whole, non-negative like the format asks, and small enough for the half-precision width, and a
 * position that arrives needing a different answer fails its own control half rather than going
 * unswept.
 */
const INTEGER_MEMBERS: Array<{ readonly where: string; readonly value: number }> = cddlIntegerPositions(
  readCddl(),
).map((where) => ({ where, value: where === 'v' ? 1 : 2 }));

describe('a position the CDDL writes `int` reads one CBOR major type', () => {
  it('refuses a whole-number float at each of them and takes the same value as an integer', () => {
    const key = generateSigningKey();
    for (const member of INTEGER_MEMBERS) {
      // Both halves go through the same writer, so the only thing apart is the major type at the one
      // position. `issueReceipt` could not produce either half: its encoder writes any whole number as
      // an integer (negative zero included, which is what the case that issues a receipt with a
      // negative zero below pins) and that is why this refusal sits in the decode rather than beside
      // these reads, where a float and the integer it imitates have already become one value.
      const asInteger = payloadWith(member.where, member.value);
      const integerBytes = signKeepingMajorTypes(
        encodeWithMajorTypes(asInteger),
        key,
        declaredProtectedHeader(key.kid),
      );
      const accepted = decodeReceipt(integerBytes);
      expect(valueAt(accepted.payload, positionOf(member.where)), `the integer at ${member.where}`).toBe(member.value);

      for (const [width, floated] of floatWidthsHolding(member.value)) {
        const bytes = signKeepingMajorTypes(
          encodeWithMajorTypes(payloadWith(member.where, floated)),
          key,
          declaredProtectedHeader(key.kid),
        );
        expect(equalBytes(bytes, integerBytes), `${member.where} written as a ${width} float`).toBe(false);
        // `BAD_PAYLOAD` is named here rather than left to the default, because the same document read
        // through the header instead of the payload answers `BAD_PROTECTED_HEADER`, and a case that
        // only heard "refused" cannot tell the two apart. The detail is the codec's own sentence for
        // the number it would not take, quoted and bounded the way every detail is. Two words of it are
        // matched, because they name the condition; the surrounding text belongs to the decoder and
        // freezing it would make a dependency upgrade this file's problem.
        const failure = expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
        expect(failure.message, `${member.where} written as a ${width}`).toContain('floating point');
        // The same answer through the door that checks the signature, which is the one a client walks
        // through. The header is well-formed and the signature is this key's, so a refusal that came
        // back as `INVALID_SIGNATURE` would be a reader complaining about the wrong part of the bytes.
        expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');
      }
    }
  });

  it('refuses a bignum at each of them, at the decode and at the field read', () => {
    const key = generateSigningKey();
    for (const member of INTEGER_MEMBERS) {
      const integerBytes = signKeepingMajorTypes(
        encodeWithMajorTypes(payloadWith(member.where, member.value)),
        key,
        declaredProtectedHeader(key.kid),
      );
      expect(
        valueAt(decodeReceipt(integerBytes).payload, positionOf(member.where)),
        `the integer at ${member.where}`,
      ).toBe(member.value);

      for (const [name, bignum] of bignumWidthsHolding(member.value)) {
        const bytes = signKeepingMajorTypes(
          encodeWithMajorTypes(payloadWith(member.where, bignum)),
          key,
          declaredProtectedHeader(key.kid),
        );
        expect(equalBytes(bytes, integerBytes), `${member.where} written as ${name}`).toBe(false);
        const failure = expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
        // The two halves are refused at two points, and the detail says which: the narrow one by the
        // decode, in the decoder's words about a bigint that need not be one, the wide one by the read
        // of the field itself. Neither is the float rule, and neither is the other.
        const detail = name.startsWith('a bignum of') ? 'bigint' : fieldSentence(positionOf(member.where));
        expect(failure.message, `${member.where} written as ${name}`).toContain(detail);
        expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');
      }
    }
  });

  it('refuses a header label written as a float, which is the merge no map can see afterwards', () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());
    // The control is a signature check and not a reader that always says yes.
    const declared = signWithHeaders(payloadBytes, key, declaredProtectedHeader(key.kid));
    expect(verifyReceipt(declared, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }).header.alg).toBe(ALG_EDDSA);

    // A declared label written a second time as a float is a fourth label to anything comparing the
    // key bytes and the same slot as the integer to a JavaScript `Map`, and core deterministic order
    // always puts the three-byte float last, so the float's value is the one that survives. The two
    // readings are each internally consistent and disagree about which parameters were signed, which
    // is a divergence no reader can settle by picking one: the document is refused before the map is
    // built, so the choice is never made.
    for (const label of DECLARED_PROTECTED_LABELS) {
      const merged = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [encodedNumber(label, 'f16'), 'x']]);
      const bytes = signKeepingMajorTypes(payloadBytes, key, merged);
      const failure = expectFailure(
        () => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }),
        'BAD_PROTECTED_HEADER',
      );
      expect(failure.message, `label ${label} carried a second time as a float`).toContain('floating point');
      expectFailure(() => decodeReceipt(bytes), 'BAD_PROTECTED_HEADER');
    }

    // The shape that reads as a well-formed header outright unless the major type is checked: the float
    // label and no integer one beside it. The map holds one key, that key is a number, and the number is
    // one the format names, so a reader looking at the map alone cannot tell it from the declared header
    // above.
    const floatAlg = new Map<unknown, unknown>([
      [encodedNumber(COSE_HEADER_ALG, 'f16'), ALG_EDDSA],
      [COSE_HEADER_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
      [COSE_HEADER_KID, key.kid],
    ]);
    const floatKid = new Map<unknown, unknown>([
      [COSE_HEADER_ALG, ALG_EDDSA],
      [COSE_HEADER_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
      [encodedNumber(COSE_HEADER_KID, 'f32'), other.kid],
    ]);
    for (const [name, header] of [['alg written under a float label', floatAlg], ['kid written under a float label', floatKid]] as const) {
      const bytes = signKeepingMajorTypes(payloadBytes, key, header);
      expectFailure(() => decodeReceipt(bytes), 'BAD_PROTECTED_HEADER');
      expect(
        expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PROTECTED_HEADER').message,
        name,
      ).toContain('floating point');
    }

    // And the one label whose value is an integer, carrying that value as a float. A reader that
    // compares -8.0 against -8 finds them equal and reports EdDSA.
    const floatedAlg = new Map<unknown, unknown>([
      [COSE_HEADER_ALG, encodedNumber(ALG_EDDSA, 'f16')],
      [COSE_HEADER_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
      [COSE_HEADER_KID, key.kid],
    ]);
    const algBytes = signKeepingMajorTypes(payloadBytes, key, floatedAlg);
    expectFailure(() => decodeReceipt(algBytes), 'BAD_PROTECTED_HEADER');
    expect(
      expectFailure(() => verifyReceipt(algBytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PROTECTED_HEADER').message,
    ).toContain('floating point');

    // Which is not the same condition as an `alg` slot holding a suite this format does not sign
    // with, or an undeclared label, and those keep the answers they had. Three refusals, none of
    // them absorbing another: the code table says a header naming another suite is a suite question
    // and a header carrying a fifth label is a membership question, and both still say so.
    const otherSuite = new Map(declaredProtectedHeader(key.kid));
    otherSuite.set(COSE_HEADER_ALG, '-8');
    expectFailure(() => decodeReceipt(signWithHeaders(payloadBytes, key, otherSuite)), 'UNSUPPORTED_ALG');
    const undeclared = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [5, 'x']]);
    expect(
      expectFailure(() => decodeReceipt(signWithHeaders(payloadBytes, key, undeclared)), 'BAD_PROTECTED_HEADER').message,
    ).toContain('a label the format does not define: 5');
  });

  it('keeps the integer rule apart from the membership rule at the same levels', () => {
    const key = generateSigningKey();
    // Two refusals at one level, named differently: the walk's answer is about a name the version
    // does not define, this one is about a value at a name it does. A document carrying both defects
    // is refused for the one the decode reaches first, which is why the pair below holds the two
    // sentences apart in both directions rather than once.
    const extraMember = membersOf(samplePayload());
    extraMember.set('surprise', 'x');
    const membership = expectFailure(() => decodeReceipt(signMembers(extraMember, key)), 'BAD_PAYLOAD');
    expect(membership.message).toContain("payload carries a member version 1 does not define: 'surprise'");
    expect(membership.message).not.toContain('floating point');

    const bothDefects = membersOf(samplePayload());
    bothDefects.set('surprise', 'x');
    bothDefects.set('iat', encodedNumber(FIXED_NOW, 'f64'));
    const decodeFirst = expectFailure(
      () =>
        decodeReceipt(
          signKeepingMajorTypes(encodeWithMajorTypes(bothDefects), key, declaredProtectedHeader(key.kid)),
        ),
      'BAD_PAYLOAD',
    );
    expect(decodeFirst.message).toContain('floating point');
    expect(decodeFirst.message).not.toContain('does not define');

    // One level down, three conditions and three sentences: `tok` holding a float is refused for the
    // float, `tok` holding an undefined member for the member, and a `tok` that is not a map at all
    // stays the reader's own answer about a map. None of the three is the other's.
    const floatedPrompt = editedNested(samplePayload(), 'tok', (nested) => nested.set('p', encodedNumber(128, 'f16')));
    const nestedFloat = expectFailure(
      () => decodeReceipt(signKeepingMajorTypes(encodeWithMajorTypes(floatedPrompt), key, declaredProtectedHeader(key.kid))),
      'BAD_PAYLOAD',
    );
    expect(nestedFloat.message).toContain('floating point');
    const nestedMember = editedNested(samplePayload(), 'tok', (nested) => nested.set('surprise', 'x'));
    expect(expectFailure(() => decodeReceipt(signMembers(nestedMember, key)), 'BAD_PAYLOAD').message).toContain(
      "tok carries a member the format does not define: 'surprise'",
    );
    const notAMap = membersOf(samplePayload());
    notAMap.set('tok', 128);
    expect(expectFailure(() => decodeReceipt(signMembers(notAMap, key)), 'BAD_PAYLOAD').message).toContain('tok must be a map');
  });

  it('leaves the map the format leaves open free to hold a float', () => {
    const key = generateSigningKey();
    // The rule reaches the two documents that declare every member they carry, and no further. The
    // unprotected map is `{ * any => any }` in the CDDL and sits outside the signature, so a float in
    // it is not an integer wearing another coat: it is a value in a place the format declares nothing
    // about, and a verifier reads no verdict out of what it holds.
    const open = new Map<unknown, unknown>([[encodedNumber(1, 'f16'), encodedNumber(2.5, 'f64')]]);
    const bytes = signKeepingMajorTypes(
      encodePayload(samplePayload()),
      key,
      declaredProtectedHeader(key.kid),
      open,
    );
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.cose.unprotected.size).toBe(1);
    expect(verified.cose.unprotected.get(1)).toBe(2.5);
    expect(verified.payload.iat).toBe(FIXED_NOW);

    // The same number, the same reader, one level in: inside the payload, where every member is
    // declared, it is refused. What closes these positions is the document's own declaredness.
    const inPayload = membersOf(samplePayload());
    inPayload.set('iat', encodedNumber(2.5, 'f64'));
    expectFailure(
      () => decodeReceipt(signKeepingMajorTypes(encodeWithMajorTypes(inPayload), key, declaredProtectedHeader(key.kid))),
      'BAD_PAYLOAD',
    );
  });
});

/**
 * The same rule read from the side that writes bytes. The block above refuses a floating-point number
 * at each position the format types as an integer, and this package is the one that refuses it, so a
 * document this package issues has to be a document this package reads.
 *
 * One value broke that, and it is the whole number JavaScript spells two ways: `Object.is(value, -0)`
 * tells negative zero apart from the `0` it prints as, while `Number.isSafeInteger(-0)` holds and
 * `-0 < 0` does not. Neither `issueReceipt` nor any guard on the way in stopped it arriving: its only
 * guard is the width of a measurement against its own kind, and four of these fields are typed
 * `number` and compared for integrality and sign, which a negative zero passes. So the fix had to sit
 * where the bytes are chosen, which is `encodeCanonical`, and not beside any one of these reads.
 */
describe('what this package issues, this package reads back', () => {
  it('carries a negative zero at an integer position as the integer zero it is', () => {
    const key = generateSigningKey();
    const base = samplePayload();
    // Four positions at once, because the writer's rule is one branch taken at every depth: two are
    // members of the payload and two sit inside the maps nested below it, where the same value had the
    // same effect.
    const negativeZero: ReceiptPayload = {
      ...base,
      iat: -0,
      epk: -0,
      att: { ...base.att, ts: -0 },
      tok: { p: -0, c: -0 },
    };
    const plainZero: ReceiptPayload = {
      ...base,
      iat: 0,
      epk: 0,
      att: { ...base.att, ts: 0 },
      tok: { p: 0, c: 0 },
    };
    expect(equalBytes(encodePayload(negativeZero), encodePayload(plainZero))).toBe(true);

    // The bytes are issued and signed, so this is the door a client walks through rather than a reader
    // handed a document it has no reason to trust. A refusal at either half below is the defect: a
    // receipt this package minted that its own verifier would not take.
    const bytes = issueReceipt(negativeZero, key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    for (const where of ['iat', 'epk', 'att.ts', 'tok.p', 'tok.c']) {
      // `Object.is(value, 0)` rather than an equality, because `value === 0` is also true of the
      // negative zero the payload was built with, and it is the sign the format refuses to carry.
      expect(Object.is(valueAt(verified.payload, where), 0), `${where} after verification`).toBe(true);
      expect(Object.is(valueAt(decodeReceipt(bytes).payload, where), 0), `${where} after decoding`).toBe(true);
    }
  });

  it('still refuses the receipt it minted whose number has no integer spelling', () => {
    const key = generateSigningKey();
    // The other half of the pairing, and the reason the case above is not a loosened reader: a value
    // with no integer spelling at all is still written as the float it is, and the reader of a
    // declared document still refuses it. `issueReceipt` guards nothing here, so the float reaches the
    // bytes, which is what the first assertion pins.
    const fractional = encodePayload(samplePayload({ iat: 2.5 }));
    expect(toHex(fractional)).toContain('f94100');
    const bytes = issueReceipt(samplePayload({ iat: 2.5 }), key);
    const failure = expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
    expect(failure.message).toContain('floating point');
    expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }), 'BAD_PAYLOAD');

    // And the whole number the float was standing for, issued the same way, reads. Without this half
    // the refusal above would only show that a minted document with a `2.5` in it is refused.
    expect(decodeReceipt(issueReceipt(samplePayload({ iat: 2 }), key)).payload.iat).toBe(2);
  });
});

function expectErrorCode(fn: () => unknown, code: string) {

  try {
    fn();
  } catch (e) {
    expect((e as ReceiptError).code).toBe(code);
    return;
  }
  throw new Error(`expected ReceiptError with code ${code}, but no error was thrown`);
}

/**
 * The refusal a parser handed back, so a case can name the condition it proves. Several documents
 * in this file fail for two reasons at once, and a code shared by both is why the detail belongs in
 * the assertion: `BAD_PAYLOAD` is what an unexpected member answers and also what a member of the
 * wrong kind answers, so a case that only checked the code would stay green with the check it is
 * about deleted. `code` defaults to the one every payload failure carries.
 */
function expectFailure(fn: () => unknown, code = 'BAD_PAYLOAD'): ReceiptError {
  try {
    fn();
  } catch (err) {
    expect((err as ReceiptError).code, `failure detail: ${(err as Error).message}`).toBe(code);
    return err as ReceiptError;
  }
  throw new Error(`expected ReceiptError with code ${code}, but no error was thrown`);
}
