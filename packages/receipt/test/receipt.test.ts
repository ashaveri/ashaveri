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
    // One list per version rather than a case per name, so these are refused by the same check: a
    // member the design ruled out of v2, and a name no version has ever used.
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
    expect(failure.message).toContain('a bstr key of 1 bytes');
  });

  it('refuses a v that is not an integer, which is the malformed half of the version read', () => {
    const key = generateSigningKey();
    // Both spellings of "not an integer at all" land here, and neither is the version code: a
    // document a reader cannot take a version from is a malformed payload, which is what the spec
    // and the code table both say. The `v: 3` case above proves the other half, that an integer
    // this package does not read is a version answer rather than a payload one.
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
