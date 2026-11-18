import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { toBase64Url, toHex } from '@ashaveri/receipt';
import {
  canonicalDigest, generatePinKeyPair, signHeadPin, verifyHeadPin, readPinEvidence,
  retainBootCapture, pinPublicKeyOfRaw, HeadPinError,
  type BootCapture, type HeadPin, type PinEvidence, type ManifestTrust,
} from './support/checkpoint-pin.js';
import { fixtureCapture, fixtureIssuerPin, fixtureManifestKeys, fixtureSuccessor } from './support/checkpoint-fixture.js';

const SCOPE = canonicalDigest({ subject: 'pin-fixture', intake: { from: 0, to: 1 } });
const HEAD = { sequence: 1, sha256: 'a'.repeat(64) };
const holder = generatePinKeyPair();
const TRUST: ManifestTrust = { mode: 'designated-keys', manifestKeys: fixtureManifestKeys };
const captures = [fixtureCapture(), fixtureCapture({ later: true })];
const ledger = Object.freeze(captures.map(retainBootCapture));
const evidence = () => readPinEvidence({ ledger, captures, trust: TRUST });
const pin = () => signHeadPin({ key: holder, head: HEAD, scope: SCOPE });
const demands = () => ({ scope: SCOPE, expectedHolder: holder, evidence: evidence() });
const readCaptured = (capture: BootCapture, trust: ManifestTrust = TRUST) =>
  readPinEvidence({ ledger: [retainBootCapture(capture)], captures: [capture], trust });

function signatureValid(value: HeadPin): boolean {
  const body = Buffer.from(`${value.document}|${value.scope}|${value.signer.keyId}|${value.signer.publicKey}|${value.head.sequence}|${value.head.sha256}`);
  return verify(null, body, createPublicKey(value.signer.publicKey), Buffer.from(value.signature, 'hex'));
}

describe('verifyHeadPin', () => {
  it('accepts a designated local holder and returns authentication and epoch evidence beside the head', () => {
    const result = verifyHeadPin(pin(), demands());
    expect(result.head).toEqual(HEAD);
    expect(result.evidence.boots).toHaveLength(2);
    expect(result.evidence.boots.every((boot) => boot.authentication.authenticated)).toBe(true);
    expect(result.evidence.boots.flatMap((boot) => boot.receipts).every((receipt) => receipt.epoch.basis === 'windows')).toBe(true);
  });

  it('refuses a self-pin whose signature Node crypto independently verifies', () => {
    const self = signHeadPin({ key: fixtureIssuerPin, head: HEAD, scope: SCOPE });
    expect(signatureValid(self)).toBe(true);
    expect(() => verifyHeadPin(self, { ...demands(), expectedHolder: fixtureIssuerPin })).toThrow(HeadPinError);
    expect(() => verifyHeadPin(self, { ...demands(), expectedHolder: fixtureIssuerPin })).toThrow(/PIN_SELF_ISSUED/u);
  });

  it('excludes a key declared only by the later boot', () => {
    const successor = { keyId: toHex(fixtureSuccessor.kid), publicKey: pinPublicKeyOfRaw(toBase64Url(fixtureSuccessor.publicKey)) };
    const claimed = { ...pin(), signer: successor };
    expect(() => verifyHeadPin(claimed, { ...demands(), expectedHolder: successor })).toThrow(/PIN_SELF_ISSUED/u);
  });

  it('refuses an untrusted holder even when the carried signature verifies', () => {
    expect(signatureValid(pin())).toBe(true);
    expect(() => verifyHeadPin(pin(), { ...demands(), expectedHolder: generatePinKeyPair() })).toThrow(/PIN_HOLDER_MISMATCH/u);
  });

  it.each([undefined, {}, { issuanceIdentities: [] }])('refuses absent or fabricated evidence: %j', (missing) => {
    expect(() => verifyHeadPin(pin(), { scope: SCOPE, expectedHolder: holder, evidence: missing as unknown as PinEvidence })).toThrow(/PIN_EVIDENCE/u);
  });

  it('refuses an absent expected holder', () => {
    expect(() => verifyHeadPin(pin(), { ...demands(), expectedHolder: undefined } as unknown as ReturnType<typeof demands>)).toThrow(/PIN_HOLDER_MISMATCH/u);
  });

  it('refuses a signer id that disagrees with its public key', () => {
    expect(() => verifyHeadPin({ ...pin(), signer: { ...holder, keyId: fixtureIssuerPin.keyId } }, demands())).toThrow(/PIN_FORM/u);
  });

  it('refuses a changed head or signature', () => {
    expect(() => verifyHeadPin({ ...pin(), head: { ...HEAD, sha256: 'b'.repeat(64) } }, demands())).toThrow(/PIN_SIGNATURE_INVALID/u);
    expect(() => verifyHeadPin({ ...pin(), signature: '0'.repeat(128) }, demands())).toThrow(/PIN_SIGNATURE_INVALID/u);
  });

  it('refuses a different scope', () => {
    expect(() => verifyHeadPin(pin(), { ...demands(), scope: 'b'.repeat(64) })).toThrow(/PIN_SCOPE_MISMATCH/u);
  });

  it.each([null, {}, { ...pin(), head: null }, { ...pin(), signature: 'bad' }, { ...pin(), scope: '' },
    { ...pin(), head: { sequence: -1, sha256: HEAD.sha256 } },
    { ...pin(), signer: { keyId: holder.keyId, publicKey: 'bad PEM' } },
    { ...pin(), signer: { keyId: holder.keyId, publicKey: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'pem', type: 'spki' }).toString() } },
  ])('refuses malformed pin/key/algorithm %#', (bad) => {
    expect(() => verifyHeadPin(bad as HeadPin, demands())).toThrow(/PIN_FORM/u);
  });

  it('folds a scope to one digest regardless of member order', () => {
    expect(canonicalDigest({ a: 1, b: { c: 2, d: [3, 4] } })).toBe(canonicalDigest({ b: { d: [3, 4], c: 2 }, a: 1 }));
  });
});

describe('captured pin evidence', () => {
  it.each([
    ['missing boot', captures.slice(0, 1)],
    ['duplicate boot', [captures[0]!, captures[0]!]],
    ['extra boot', [...captures, { ...captures[0]!, boot: 'extra' }]],
    ['missing receipt', [{ ...captures[0]!, receipts: [] }, captures[1]!]],
    ['duplicate receipt', [{ ...captures[0]!, receipts: [captures[0]!.receipts[0]!, captures[0]!.receipts[0]!] }, captures[1]!]],
    ['reassigned boot', [{ ...captures[0]!, receipts: captures[1]!.receipts }, { ...captures[1]!, receipts: captures[0]!.receipts }]],
    ['changed receipt id', [{ ...captures[0]!, receipts: [{ ...captures[0]!.receipts[0]!, id: 'changed' }] }, captures[1]!]],
    ['changed receipt bytes', [{ ...captures[0]!, receipts: [{ ...captures[0]!.receipts[0]!, bytes: new Uint8Array(10) }] }, captures[1]!]],
    ['changed manifest', [{ ...captures[0]!, manifest: captures[1]!.manifest }, captures[1]!]],
  ] as const)('refuses %s against the original ledger', (_name, candidate) => {
    expect(() => readPinEvidence({ ledger, captures: candidate, trust: TRUST })).toThrow(/PIN_EVIDENCE/u);
  });

  it('retains immutable digest records separate from mutable candidate bytes', () => {
    const candidate = fixtureCapture();
    const original = retainBootCapture(candidate);
    const saved = original.receipts[0]!.sha256;
    candidate.receipts[0]!.bytes[0] = candidate.receipts[0]!.bytes[0]! ^ 1;
    expect(original.receipts[0]!.sha256).toBe(saved);
    expect(Object.isFrozen(original)).toBe(true);
    expect(Object.isFrozen(original.receipts)).toBe(true);
    expect(Object.isFrozen(original.receipts[0])).toBe(true);
    expect(() => readPinEvidence({ ledger: [original], captures: [candidate], trust: TRUST })).toThrow(/PIN_EVIDENCE/u);
  });

  it('rejects an absent ledger and duplicate original acknowledgements', () => {
    expect(() => readPinEvidence({ ledger: undefined, captures, trust: TRUST } as unknown as Parameters<typeof readPinEvidence>[0])).toThrow(/PIN_EVIDENCE/u);
    expect(() => readPinEvidence({ ledger: [ledger[0]!, ledger[0]!], captures, trust: TRUST })).toThrow(/PIN_EVIDENCE/u);
    const duplicate = { ...captures[1]!, receipts: captures[0]!.receipts };
    expect(() => readPinEvidence({ ledger: [ledger[0]!, retainBootCapture(duplicate)], captures: [captures[0]!, duplicate], trust: TRUST })).toThrow(/PIN_EVIDENCE/u);
  });

  it('reports unsigned epoch-zero evidence as TOFU, not authenticated', () => {
    const read = readCaptured(fixtureCapture({ unsigned: true, windowless: true }), { mode: 'synthetic-tofu' });
    expect(read.boots[0]!.authentication).toMatchObject({ authenticated: false, demanded: false, sealed: false });
    expect(read.boots[0]!.authentication.advisory).toContain('trust-on-first-use');
    expect(read.boots[0]!.receipts[0]!.epoch).toMatchObject({ basis: 'current-epoch', epoch: 0 });
  });

  it('does not use empty stores as evidence for a nonempty pinned scope', () => {
    const empty = { ...fixtureCapture({ windowless: true }), receipts: [] };
    const read = readCaptured(empty);
    expect(read.boots[0]!.receipts).toEqual([]);
    expect(() => verifyHeadPin(pin(), { ...demands(), evidence: read })).toThrow(/PIN_EVIDENCE/u);
    expect(() => verifyHeadPin(pin(), { ...demands(), evidence: readPinEvidence({ ledger: [], captures: [], trust: TRUST }) })).toThrow(/PIN_EVIDENCE/u);
  });

  it('refuses empty deployment key arrays through the SDK parser', () => {
    expect(() => readCaptured(fixtureCapture({ document: (value) => { value['keys'] = []; } }))).toThrow(expect.objectContaining({ code: 'BAD_MANIFEST' }));
  });

  it('refuses a manifest kid/public-key mismatch even in an unused row', () => {
    const bad = fixtureCapture({ later: true, document: (value) => {
      const keys = value['keys'] as { kid: string }[];
      keys[0]!.kid = '0'.repeat(64);
    } });
    expect(() => readCaptured(bad)).toThrow(/PIN_EVIDENCE/u);
  });

  it('requires designated manifest authentication instead of downgrading to TOFU', () => {
    expect(() => readCaptured(fixtureCapture({ unsigned: true }))).toThrow(expect.objectContaining({ code: 'MANIFEST_NOT_AUTHENTICATED' }));
    expect(() => readCaptured(fixtureCapture(), { mode: 'designated-keys', manifestKeys: {} })).toThrow(/PIN_EVIDENCE/u);
    expect(() => readCaptured(fixtureCapture(), { mode: 'designated-keys', manifestKeys: { [holder.keyId]: toBase64Url(fixtureSuccessor.publicKey) } })).toThrow(expect.objectContaining({ code: 'MANIFEST_NOT_AUTHENTICATED' }));
    expect(() => readPinEvidence({ ledger, captures, trust: undefined } as unknown as Parameters<typeof readPinEvidence>[0])).toThrow(/PIN_EVIDENCE/u);
  });

  it('refuses a captured invalid manifest signature under its designated key', () => {
    const bad = fixtureCapture();
    bad.manifest[bad.manifest.length - 1] = bad.manifest[bad.manifest.length - 1]! ^ 1;
    expect(() => readCaptured(bad)).toThrow(expect.objectContaining({ code: 'MANIFEST_SIGNATURE_INVALID' }));
  });

  it('verifies the actual acknowledged receipt signature, not just its declared kid', () => {
    const bad = fixtureCapture();
    const bytes = bad.receipts[0]!.bytes;
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    expect(() => readCaptured(bad)).toThrow(expect.objectContaining({ code: 'INVALID_SIGNATURE' }));
  });

  it('refuses a receipt reconciled against another boot manifest', () => {
    expect(() => readCaptured({ ...captures[0]!, manifest: fixtureCapture({ later: true, document: (value) => {
      value['keys'] = (value['keys'] as unknown[]).slice(1);
    } }).manifest })).toThrow(expect.objectContaining({ code: 'UNKNOWN_KEY' }));
  });

  it('refuses receipt issuer/instance disagreement', () => {
    for (const field of ['iss', 'ins']) {
      expect(() => readCaptured(fixtureCapture({ document: (value) => { value[field] = 'other'; } }))).toThrow(/PIN_EVIDENCE/u);
    }
  });

  it('uses the SDK epoch reader for undeclared epochs and retired-key windows', () => {
    expect(() => readCaptured(fixtureCapture({ payload: { epk: 2 } }))).toThrow(/MANIFEST_EPOCH_UNDECLARED/u);
    expect(() => readCaptured(fixtureCapture({ later: true, payload: { iat: 100, itm: [{ t: 100, d: new Uint8Array(32) }] } }))).toThrow(/MANIFEST_EPOCH_DISAGREES/u);
  });
});
