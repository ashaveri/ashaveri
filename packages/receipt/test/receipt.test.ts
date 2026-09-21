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
import type { Marking, ReceiptPayload, ReceiptPayloadV1, ReceiptPayloadV2, SigningKey } from '../src/index.js';
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

const FIXED_NOW = 1_772_000_000;

function samplePayload(overrides: Partial<ReceiptPayloadV1> = {}): ReceiptPayloadV1 {
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
    ...overrides,
  };
}

describe('COSE_Sign1 receipt codec', () => {
  it('round-trips: issue, verify, decode agree', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);

    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });
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
    expectErrorCode(() => verifyReceipt(tampered, { publicKey: key.publicKey, now: FIXED_NOW }), 'INVALID_SIGNATURE');
  });

  it('rejects a signature from a different key', () => {
    const signer = generateSigningKey();
    const other = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), signer);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: other.publicKey, now: FIXED_NOW }), 'KID_MISMATCH');
  });

  it('resolves keys via resolveKey by kid', () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const resolver = (kid: Uint8Array) => (equalBytes(kid, keyId(key.publicKey)) ? key.publicKey : undefined);
    expect(() => verifyReceipt(bytes, { resolveKey: resolver, now: FIXED_NOW })).not.toThrow();
    const badResolver = () => other.publicKey;
    expectErrorCode(() => verifyReceipt(bytes, { resolveKey: badResolver, now: FIXED_NOW }), 'KID_MISMATCH');
    expectErrorCode(() => verifyReceipt(bytes, { resolveKey: () => undefined, now: FIXED_NOW }), 'UNKNOWN_KEY');
  });

  it('enforces nonce echo', () => {
    const key = generateSigningKey();
    const nonce = randomNonce();
    const bytes = issueReceipt(samplePayload({ nce: nonce }), key);
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, expectedNonce: nonce, now: FIXED_NOW })).not.toThrow();
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, expectedNonce: randomNonce(), now: FIXED_NOW }),
      'NONCE_MISMATCH',
    );
  });

  it('enforces receipt and evidence freshness windows', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(samplePayload(), key);
    const now = FIXED_NOW + 3600;
    expect(() => verifyReceipt(bytes, { publicKey: key.publicKey, now, freshnessSeconds: 7200, evidenceFreshnessSeconds: 7200 })).not.toThrow();
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, now, freshnessSeconds: 60 }), 'STALE_RECEIPT');
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, now, freshnessSeconds: 7200, evidenceFreshnessSeconds: 60 }),
      'STALE_EVIDENCE',
    );
  });

  it('rejects structurally invalid payloads with BAD_PAYLOAD', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    // A 15-byte nonce satisfies the field's type but not the codec's fixed 16-byte
    // length, so the payload this line builds is structurally invalid.
    const bad = { ...payload, nce: new Uint8Array(15) };
    const bytes = issueReceipt(bad as ReceiptPayload, key);
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'BAD_PAYLOAD');
  });

  it('rejects a negative timestamp with BAD_PAYLOAD', () => {
    const key = generateSigningKey();
    const base = samplePayload();
    // The spec fixes every integer as non-negative, so a signed document that breaks
    // that rule is malformed even when its signature is valid.
    const negativeIat = issueReceipt(samplePayload({ iat: -1 }), key);
    expectErrorCode(() => verifyReceipt(negativeIat, { publicKey: key.publicKey, now: FIXED_NOW }), 'BAD_PAYLOAD');
    const negativeEvidenceTs = issueReceipt(samplePayload({ att: { ...base.att, ts: -1 } }), key);
    expectErrorCode(
      () => verifyReceipt(negativeEvidenceTs, { publicKey: key.publicKey, now: FIXED_NOW }),
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
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.payload.meas.m).toHaveLength(48);
    expect(equalBytes(verified.payload.meas.m, launchDigest)).toBe(true);
  });

  it('carries a 32-byte software measurement', () => {
    const key = generateSigningKey();
    const digest = sha256(new TextEncoder().encode('deployment image'));
    const bytes = issueReceipt(samplePayload({ meas: { tee: 'software', m: digest } }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.payload.meas.tee).toBe('software');
    expect(equalBytes(verified.payload.meas.m, digest)).toBe(true);
  });

  it('carries the TDX measurement for a claim that also names an accelerator', () => {
    const key = generateSigningKey();
    const mrtd = new Uint8Array(48).fill(11);
    const bytes = issueReceipt(samplePayload({ meas: { tee: 'tdx+gpucc', m: mrtd } }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });
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

  it('refuses a receipt signed under the superseded card-named composite', () => {
    // Signed past issueReceipt rather than built through it: the point is that a
    // verifier no longer recognises the label, so the bytes have to exist first.
    const key = generateSigningKey();
    const foreign = signCoseSign1(
      encodePayload(samplePayload({ meas: { tee: 'snp+h100cc' as never, m: new Uint8Array(48).fill(7) } })),
      key,
    );
    let caught: ReceiptError | null = null;
    try {
      verifyReceipt(foreign, { publicKey: key.publicKey, now: FIXED_NOW });
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
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'BAD_PAYLOAD');
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
    const verified = verifyReceipt(declared, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.payload.mdl).toBe('meta-llama/Llama-3.1-8B-Instruct');
    expect(equalBytes(verified.cose.payloadBytes, payloadBytes)).toBe(true);
    // And the control is a signature check rather than a reader that always answers yes: one byte of
    // the signature moved, the same document comes back refused for its signature and not for its
    // header, which is what makes the acceptance above evidence about the label below.
    const moved = new Uint8Array(declared);
    moved[moved.length - 1]! ^= 0x01;
    expectFailure(() => verifyReceipt(moved, { publicKey: key.publicKey, now: FIXED_NOW }), 'INVALID_SIGNATURE');

    // One more label and the same rule for making the bytes. Label 5 is not one `receipt.cddl` names,
    // and it is inside the `Sig_structure`, so a reader that took the three it knows and returned
    // those handed on a smaller document than the one the issuer signed. It is refused by number.
    const fifth = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid), [5, 'x']]);
    const refused = signWithHeaders(payloadBytes, key, fifth);
    const failure = expectFailure(
      () => verifyReceipt(refused, { publicKey: key.publicKey, now: FIXED_NOW }),
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
      () => verifyReceipt(signWithHeaders(payloadBytes, key, negative), { publicKey: key.publicKey, now: FIXED_NOW }),
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
    const passed = verifyReceipt(unsignedFifth, { publicKey: key.publicKey, now: FIXED_NOW });
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
      () => verifyReceipt(signWithHeaders(payloadBytes, key, noKid), { publicKey: key.publicKey, now: FIXED_NOW }),
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
      () => verifyReceipt(signWithHeaders(payloadBytes, key, noAlg), { publicKey: key.publicKey, now: FIXED_NOW }),
      'UNSUPPORTED_ALG',
    );
    expect(failure.message).toContain('alg must be an integer label, got undefined');
    // And the other shape of the same parameter, a suite this format does not sign with, answers under
    // that code too: the split is between the map and the algorithm, not between an absent `alg` and a
    // wrong one.
    const wrongAlg = new Map<unknown, unknown>(declaredProtectedHeader(key.kid));
    wrongAlg.set(COSE_HEADER_ALG, -7);
    expectFailure(
      () => verifyReceipt(signWithHeaders(payloadBytes, key, wrongAlg), { publicKey: key.publicKey, now: FIXED_NOW }),
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
    const empty = verifyReceipt(openBytes, { publicKey: key.publicKey, now: FIXED_NOW });
    const filled = verifyReceipt(rivalBytes, { publicKey: key.publicKey, now: FIXED_NOW });
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

    // And the two keys that are integers, just not integers a label can be. This is the case where the
    // message used to claim the opposite of the truth: a tag 2 bignum, and a CBOR integer the encoder
    // wrote in major type 0 but too wide for the decoder to hand back as a `number`, both arrive as
    // `bigint`, which is an integer outside the range a COSE label occupies. Calling either "not an
    // integer" points whoever reads the log at a type bug rather than at the label space, which is the
    // one place the document is wrong. The second is here because it is not a bignum on the wire at
    // all, and a message that named it one would be the same defect wearing a different word.
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
 * The digest an unmarked v2 receipt carries: the marked region is empty, so `mk.d` is the digest of
 * no bytes at all. Spelled out here rather than derived because it is the value that turns "not
 * marked" into a claim a reader can check instead of a hole where a field would have been.
 */
const EMPTY_REGION_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** Stands in for the response bytes a `provenance-v1` mark occupies. */
const MARKED_REGION = new TextEncoder().encode(
  '{"ashaveri":{"marking":{"sch":"ashaveri/provenance-v1","gen":"ai","at":1772000000}}}',
);

function markedPayload(mk: Marking = { sch: 'provenance-v1', d: sha256(MARKED_REGION) }): ReceiptPayloadV2 {
  return { ...samplePayload(), v: 2, mk };
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
  if (payload.v === 2) {
    members.push(['mk', new Map<string, unknown>([['sch', payload.mk.sch], ['d', payload.mk.d]])]);
  }
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

/** Narrows a parsed payload to the marked shape, for the cases that came here looking for `mk`. */
function marked(payload: ReceiptPayload): ReceiptPayloadV2 {
  if (payload.v !== 2) throw new Error(`expected a v2 payload, got version ${payload.v}`);
  return payload;
}

describe('receipt payload v2 and the versions a call accepts', () => {
  it('round-trips a well-formed marked receipt', () => {
    const key = generateSigningKey();
    const payload = markedPayload();
    const verified = verifyReceipt(issueReceipt(payload, key), { publicKey: key.publicKey, now: FIXED_NOW });

    expect(verified.payload.v).toBe(2);
    expect(marked(verified.payload).mk.sch).toBe('provenance-v1');
    expect(equalBytes(marked(verified.payload).mk.d, sha256(MARKED_REGION))).toBe(true);
    // Every v1 field still arrives, and the re-encode is the bytes that were signed.
    expect(verified.payload.mdl).toBe(payload.mdl);
    expect(equalBytes(encodePayload(verified.payload), verified.cose.payloadBytes)).toBe(true);
  });

  it('encodes a marked payload exactly as the format lays out its members', () => {
    const payload = markedPayload();
    expect(equalBytes(encodePayload(payload), encodeCanonical(membersOf(payload)))).toBe(true);
  });

  it("parses an unmarked v2 receipt carrying the empty region's digest", () => {
    const key = generateSigningKey();
    const empty = sha256(new Uint8Array(0));
    expect(toHex(empty)).toBe(EMPTY_REGION_SHA256_HEX);
    const bytes = issueReceipt(markedPayload({ sch: 'none', d: empty }), key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });

    expect(marked(verified.payload).mk.sch).toBe('none');
    expect(toHex(marked(verified.payload).mk.d)).toBe(EMPTY_REGION_SHA256_HEX);
  });

  it('refuses a v2 payload with no mk as a payload failure, not as an unmarked receipt', () => {
    const key = generateSigningKey();
    const members = membersOf(markedPayload());
    members.delete('mk');
    const bytes = signMembers(members, key);
    // The detail is the assertion here. Every member this document is missing is also a wrong-kind
    // read, so the code alone would still be BAD_PAYLOAD if the requirement that `mk` be present
    // were deleted: only the sentence says the refusal was reached for that reason.
    const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }));
    expect(failure.message).toContain('v2 requires an mk member');
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
    const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'UNSUPPORTED_SCHEME');
    expect(failure.message).toContain("marking scheme 'provenance-v2'");
  });

  it('refuses a v1 payload carrying mk, because a payload map is closed', () => {
    const key = generateSigningKey();
    const members = membersOf(samplePayload());
    // Fourteen members, thirteen of them v1's, and the fourteenth is the marking attestation. Read
    // with that member dropped, this is a verified v1 receipt whose holder has been told nothing
    // about a mark, which is the same silence `mk` was given a version to refuse. The map is
    // closed, so the document is refused instead, and the detail names the member it named.
    members.set('mk', new Map<string, unknown>([['sch', 'none'], ['d', sha256(new Uint8Array(0))]]));
    const bytes = signMembers(members, key);
    const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }));
    expect(failure.message).toContain("member version 1 does not define: 'mk'");
    // Which way the document was opened changes nothing: the refusal belongs to the payload, not to
    // the signature check, so an unread receipt answers the same way as a verified one.
    expectFailure(() => decodeReceipt(bytes), 'BAD_PAYLOAD');
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
        () => verifyReceipt(signMembers(members, key), { publicKey: key.publicKey, now: FIXED_NOW }),
      );
      expect(failure.message, `${name} on a v2 payload`).toContain(`member version 2 does not define: '${name}'`);
    }
    // A key that is not a text label is not a member either, and no CDDL map admits one.
    const foreignKey = new Map<unknown, unknown>([...membersOf(samplePayload()), [new Uint8Array([7]), 'x']]);
    const failure = expectFailure(
      () => verifyReceipt(signMembers(foreignKey, key), { publicKey: key.publicKey, now: FIXED_NOW }),
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
      () => verifyReceipt(signMembers(members, key), { publicKey: key.publicKey, now: FIXED_NOW }),
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
    // and the code table both say. The `v: 3` case further down this block proves the other half,
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

  it("refuses a v2 receipt a caller narrowed away with the version's own code", () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(markedPayload(), key);
    expectErrorCode(
      () => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW, acceptedVersions: [1] }),
      'UNSUPPORTED_VERSION',
    );
  });

  it('refuses a version this package cannot parse with the same code', () => {
    const key = generateSigningKey();
    const members = membersOf(samplePayload());
    members.set('v', 3);
    const bytes = signMembers(members, key);
    // One code for both refusals on purpose: which side of a boundary a number sits on is a fact
    // about releases, and two answers would let a caller find it out.
    expectErrorCode(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'UNSUPPORTED_VERSION');
    expectErrorCode(() => decodeReceipt(bytes), 'UNSUPPORTED_VERSION');

    // Closedness is settled after the version, so these two refusals never compete for one document:
    // a version a reader cannot take answers with the version code whichever members it carries, and
    // so does a version a caller narrowed away. Without this, the one answer the format promises
    // would depend on what else the bytes happened to hold.
    const unreadable = membersOf(samplePayload());
    unreadable.set('v', 3);
    unreadable.set('mk', new Map<string, unknown>());
    const unreadableBytes = signMembers(unreadable, key);
    expectErrorCode(() => verifyReceipt(unreadableBytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'UNSUPPORTED_VERSION');
    expectErrorCode(() => decodeReceipt(unreadableBytes), 'UNSUPPORTED_VERSION');

    const narrowed = membersOf(markedPayload());
    narrowed.set('not_a_member', 'x');
    const narrowedBytes = signMembers(narrowed, key);
    expectErrorCode(
      () => verifyReceipt(narrowedBytes, { publicKey: key.publicKey, now: FIXED_NOW, acceptedVersions: [1] }),
      'UNSUPPORTED_VERSION',
    );
    expectErrorCode(() => decodeReceipt(narrowedBytes, { acceptedVersions: [1] }), 'UNSUPPORTED_VERSION');
  });

  it('refuses both versions when the accepted set is empty', () => {
    const key = generateSigningKey();
    const v1 = issueReceipt(samplePayload(), key);
    const v2 = issueReceipt(markedPayload(), key);
    for (const bytes of [v1, v2]) {
      expectErrorCode(
        () => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW, acceptedVersions: [] }),
        'UNSUPPORTED_VERSION',
      );
      expectErrorCode(() => decodeReceipt(bytes, { acceptedVersions: [] }), 'UNSUPPORTED_VERSION');
    }
  });

  it('verifies a v1 receipt with nothing set and nothing gained', () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const bytes = issueReceipt(payload, key);
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });

    expect(verified.payload.v).toBe(1);
    expect(equalBytes(encodePayload(verified.payload), verified.cose.payloadBytes)).toBe(true);
    // The thirteen members are the whole document, in the order the format lists them and the twin
    // writes them: a v1 receipt has no marking to be read out of it, and its JSON projection has
    // neither gained a member nor reordered the ones it has. Sorted, this assertion would hold for
    // any key order, and `receiptToJson` claims order is part of what it publishes. What pins the
    // committed twin's order is the vector-drift step of the continuous build regenerating
    // `packages/fixtures/data` and refusing a diff; this is the guard that says which order.
    const twin = receiptToJson(verified.payload, verified.cose.signature, verified.header.kid);
    expect(Object.keys(twin.payload)).toEqual([
      'v', 'iss', 'ins', 'iat', 'nce', 'req', 'res', 'mdl', 'wts', 'meas', 'att', 'epk', 'tok',
    ]);
  });

  it('decodeReceipt reads a marked receipt by default and refuses it when narrowed', () => {
    const key = generateSigningKey();
    const bytes = issueReceipt(markedPayload(), key);

    expect(marked(decodeReceipt(bytes).payload).mk.sch).toBe('provenance-v1');
    expectErrorCode(() => decodeReceipt(bytes, { acceptedVersions: [1] }), 'UNSUPPORTED_VERSION');
    expect(marked(decodeReceipt(bytes, { acceptedVersions: [1, 2] }).payload).mk.sch).toBe('provenance-v1');
  });
});

/**
 * The members of a payload, with `edit` applied inside the map the format puts at `owner`. The maps
 * below the payload are what the closedness rule reaches, and every case here has to be a document
 * that is whole except for what the edit wrote. `membersOf` builds fresh nested maps on every call, so
 * an edit cannot leak from one case into the next.
 */
function editedNested(
  payload: ReceiptPayload,
  owner: string,
  edit: (nested: Map<unknown, unknown>) => void,
): Map<string, unknown> {
  const members = membersOf(payload);
  const nested = members.get(owner);
  if (!(nested instanceof Map)) throw new Error(`the corpus carries no ${owner} map to edit`);
  edit(nested);
  return members;
}

/** A document of the payload version the closure walk names, which is the whole corpus here. */
function payloadForVersion(version: string): ReceiptPayload {
  if (version === '1') return samplePayload();
  if (version === '2') return markedPayload();
  throw new Error(`this corpus has no document for payload version ${version}`);
}

/**
 * One case per map per version, read off the structure the walk enforces rather than spelled out
 * here. The schema test derives the twin's matrices from this same structure, so a map the format
 * gains arrives in each of them on the day it lands and a version with no document here fails the
 * run rather than covering one case fewer.
 */
function nestedCases(): Array<[ReceiptPayload, string]> {
  return Object.entries(receiptParser.DEFINED_MAPS).flatMap(
    ([version, defined]) =>
      Object.keys(defined.nested ?? []).map((key): [ReceiptPayload, string] => [payloadForVersion(version), key]),
  );
}

describe('the payload map and every map nested inside it are closed', () => {
  it('refuses an undefined member inside meas, att, tok and mk, and names the one it refused', () => {
    const key = generateSigningKey();
    // Both halves of every case below: the unedited document verifies, so a refusal is the added
    // member's answer and not one this corpus was already failing for.
    for (const version of Object.keys(receiptParser.DEFINED_MAPS)) {
      const unedited = issueReceipt(payloadForVersion(version), key);
      expect(() => verifyReceipt(unedited, { publicKey: key.publicKey, now: FIXED_NOW })).not.toThrow();
    }

    for (const [payload, owner] of nestedCases()) {
      const bytes = signMembers(editedNested(payload, owner, (nested) => nested.set('surprise', 'x')), key);
      const failure = expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }));
      expect(
        failure.message,
        `a v${payload.v} payload with an undefined member inside ${owner}`,
      ).toContain(`${owner} carries a member the format does not define: 'surprise'`);
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
    const refusal = expectFailure(() => verifyReceipt(foreignKey, { publicKey: key.publicKey, now: FIXED_NOW }));
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
    const misTyped = expectFailure(() => verifyReceipt(signMembers(stringPrompt, key), { publicKey: key.publicKey, now: FIXED_NOW }));
    expect(misTyped.message).toContain('tok.p must be a non-negative integer');

    // A member the format makes a map and the bytes did not deliver one is still the reader's answer,
    // because the walk has no map to enter and cannot claim a membership failure it cannot see.
    const measIsText = membersOf(samplePayload());
    measIsText.set('meas', 'snp');
    const meas = expectFailure(() => verifyReceipt(signMembers(measIsText, key), { publicKey: key.publicKey, now: FIXED_NOW }));
    expect(meas.message).toContain('meas must be a map');

    const mkIsText = membersOf(markedPayload());
    mkIsText.set('mk', 'none');
    const mark = expectFailure(() => verifyReceipt(signMembers(mkIsText, key), { publicKey: key.publicKey, now: FIXED_NOW }));
    expect(mark.message).toContain('mk must be a map');
  });
});

/**
 * The bytes of a document in which every number keeps the major type it was written with. The
 * package's own canonical writer cannot produce these: `encodeCanonical` ignores a boxed number's
 * original encoding on purpose, because a whole number in this format is an integer and the encoder
 * must not be able to emit anything else. So a case that wants to hand the reader a float where the
 * CDDL names an integer has to step outside that writer and use the plain one, which honours the
 * width the value carries.
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
 * The corpus payload with one integer position rewritten. The three top-level members are set on the
 * map itself; the two below a nested map go through `editedNested`, which is the same route the
 * closure cases take and leaves every other member exactly as `membersOf` wrote it.
 */
function payloadWith(where: string, value: unknown): Map<string, unknown> {
  if (where === 'v' || where === 'iat' || where === 'epk') {
    const members = membersOf(samplePayload());
    members.set(where, value);
    return members;
  }
  const [owner, name] = where.split('.') as ['att' | 'tok', string];
  return editedNested(samplePayload(), owner, (nested) => nested.set(name, value));
}

/** What a parsed payload carries at one of those positions, read the same way the cases name them. */
function valueAt(payload: ReceiptPayload, where: string): unknown {
  let cursor: unknown = payload;
  for (const part of where.split('.')) cursor = (cursor as Record<string, unknown>)[part];
  return cursor;
}

/** Every position `receipt.cddl` writes `int` for, with the value each case puts there. */
const INTEGER_MEMBERS: Array<{ readonly where: string; readonly value: number }> = [
  { where: 'v', value: 1 },
  { where: 'iat', value: 2 },
  { where: 'epk', value: 2 },
  { where: 'att.ts', value: 2 },
  { where: 'tok.p', value: 2 },
  { where: 'tok.c', value: 2 },
];

describe('a position the CDDL writes `int` reads one CBOR major type', () => {
  it('refuses a whole-number float at each of them and takes the same value as an integer', () => {
    const key = generateSigningKey();
    for (const member of INTEGER_MEMBERS) {
      // Both halves go through the same writer, so the only thing apart is the major type at the one
      // position. `issueReceipt` could not produce either half: its encoder turns a whole number into
      // an integer whatever the caller wrote, which is why this refusal sits in the decode rather than
      // beside these reads, where a float and the integer it imitates have already become one value.
      const asInteger = payloadWith(member.where, member.value);
      const integerBytes = signKeepingMajorTypes(
        encodeWithMajorTypes(asInteger),
        key,
        declaredProtectedHeader(key.kid),
      );
      const accepted = decodeReceipt(integerBytes);
      expect(valueAt(accepted.payload, member.where), `the integer at ${member.where}`).toBe(member.value);

      for (const [width, floated] of floatWidthsHolding(member.value)) {
        const bytes = signKeepingMajorTypes(
          encodeWithMajorTypes(payloadWith(member.where, floated)),
          key,
          declaredProtectedHeader(key.kid),
        );
        expect(equalBytes(bytes, integerBytes), `${member.where} written as a ${width} float`).toBe(false);
        // `BAD_PAYLOAD` is the code the format already uses for a member of the wrong kind, and the
        // detail is the codec's own sentence for the number it would not take, quoted and bounded the
        // way every detail is. Two words of it are matched here, because they name the condition; the
        // surrounding text belongs to the decoder and freezing it would make a dependency upgrade this
        // file's problem.
        const failure = expectFailure(() => decodeReceipt(bytes));
        expect(failure.message, `${member.where} written as a ${width} float`).toContain('floating point');
        // The same answer through the door that checks the signature, which is the one a client walks
        // through. The header is well-formed and the signature is this key's, so a refusal that came
        // back as `INVALID_SIGNATURE` would be a reader complaining about the wrong part of the bytes.
        expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }));
      }
    }
  });

  it('refuses a header label written as a float, which is the merge no map can see afterwards', () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const payloadBytes = encodePayload(samplePayload());
    // The control is a signature check and not a reader that always says yes.
    const declared = signWithHeaders(payloadBytes, key, declaredProtectedHeader(key.kid));
    expect(verifyReceipt(declared, { publicKey: key.publicKey, now: FIXED_NOW }).header.alg).toBe(ALG_EDDSA);

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
        () => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }),
        'BAD_PROTECTED_HEADER',
      );
      expect(failure.message, `label ${label} carried a second time as a float`).toContain('floating point');
      expectFailure(() => decodeReceipt(bytes), 'BAD_PROTECTED_HEADER');
    }

    // The shape that used to read as a well-formed header outright: the float label and no integer
    // one beside it. The map held one key, that key was a number, and the number was one the format
    // names, so a reader looking at the map could not tell it from the declared header above.
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
        expectFailure(() => verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'BAD_PROTECTED_HEADER').message,
        name,
      ).toContain('floating point');
    }

    // And the one label whose value is an integer, carrying that value as a float. The reader used to
    // compare -8.0 against -8, find them equal, and report EdDSA.
    const floatedAlg = new Map<unknown, unknown>([
      [COSE_HEADER_ALG, encodedNumber(ALG_EDDSA, 'f16')],
      [COSE_HEADER_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
      [COSE_HEADER_KID, key.kid],
    ]);
    const algBytes = signKeepingMajorTypes(payloadBytes, key, floatedAlg);
    expectFailure(() => decodeReceipt(algBytes), 'BAD_PROTECTED_HEADER');
    expect(
      expectFailure(() => verifyReceipt(algBytes, { publicKey: key.publicKey, now: FIXED_NOW }), 'BAD_PROTECTED_HEADER').message,
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
    const membership = expectFailure(() => decodeReceipt(signMembers(extraMember, key)));
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
    );
    expect(decodeFirst.message).toContain('floating point');
    expect(decodeFirst.message).not.toContain('does not define');

    // One level down, three conditions and three sentences: `tok` holding a float is refused for the
    // float, `tok` holding an undefined member for the member, and a `tok` that is not a map at all
    // stays the reader's own answer about a map. None of the three is the other's.
    const floatedPrompt = editedNested(samplePayload(), 'tok', (nested) => nested.set('p', encodedNumber(128, 'f16')));
    const nestedFloat = expectFailure(
      () => decodeReceipt(signKeepingMajorTypes(encodeWithMajorTypes(floatedPrompt), key, declaredProtectedHeader(key.kid))),
    );
    expect(nestedFloat.message).toContain('floating point');
    const nestedMember = editedNested(samplePayload(), 'tok', (nested) => nested.set('surprise', 'x'));
    expect(expectFailure(() => decodeReceipt(signMembers(nestedMember, key))).message).toContain(
      "tok carries a member the format does not define: 'surprise'",
    );
    const notAMap = membersOf(samplePayload());
    notAMap.set('tok', 128);
    expect(expectFailure(() => decodeReceipt(signMembers(notAMap, key))).message).toContain('tok must be a map');
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
    const verified = verifyReceipt(bytes, { publicKey: key.publicKey, now: FIXED_NOW });
    expect(verified.cose.unprotected.size).toBe(1);
    expect(verified.cose.unprotected.get(1)).toBe(2.5);
    expect(verified.payload.iat).toBe(FIXED_NOW);

    // The same number, the same reader, one level in: inside the payload, where every member is
    // declared, it is refused. What closes these positions is the document's own declaredness.
    const inPayload = membersOf(samplePayload());
    inPayload.set('iat', encodedNumber(2.5, 'f64'));
    expectFailure(
      () => decodeReceipt(signKeepingMajorTypes(encodeWithMajorTypes(inPayload), key, declaredProtectedHeader(key.kid))),
    );
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
