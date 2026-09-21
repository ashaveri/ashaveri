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
  RECEIPT_CONTENT_TYPE,
  buildProtectedHeader,
} from '../src/cose.js';
import { ed25519 } from '@noble/curves/ed25519';
import { Tag } from 'cbor2';
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
    // and the refusal below is the required-parameter rule. Both halves answer under one code, and
    // this is the case that says closing the map did not replace asking for what it must hold.
    const noKid = new Map<unknown, unknown>([...declaredProtectedHeader(key.kid)]);
    noKid.delete(COSE_HEADER_KID);
    const failure = expectFailure(
      () => verifyReceipt(signWithHeaders(payloadBytes, key, noKid), { publicKey: key.publicKey, now: FIXED_NOW }),
      'BAD_PROTECTED_HEADER',
    );
    expect(failure.message).toContain('kid must be a 32-byte bstr');
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
