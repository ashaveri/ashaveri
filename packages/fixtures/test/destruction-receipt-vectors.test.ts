import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DESTRUCTION_COPY_CLASSES,
  DESTRUCTION_OBJECT_KINDS,
  DESTRUCTION_RECEIPT_CONTENT_TYPE,
  DESTRUCTION_RECEIPT_ENTRY_MEMBERS,
  DESTRUCTION_RECEIPT_MANIFEST_MEMBERS,
  DESTRUCTION_UNREACHABLE_COPY_CLASSES,
  ReceiptError,
  decodeCanonical,
  decodeDestructionReceipt,
  fromBase64Url,
  signDestructionReceipt,
  signingKeyFromSeed,
  toHex,
  verifyDestructionReceipt,
} from '@ashaveri/receipt';
import {
  loadDestructionReceiptVectors,
  type DestructionReceiptVerificationInput,
} from '../src/index.js';

/**
 * The published destruction receipt suite, read as bytes and run through the shipped readers.
 *
 * A vector file claims that a port holding only these bytes and the published format reaches the same answers
 * this package reaches, so nothing here trusts a published verdict without recomputing it from the document the
 * row carries. Three things are asked of the suite: that both doors give the answers each row states, that
 * every accepted row states a reach for every copy class and none at the class the format declares out of
 * reach, and that the registries the file names are the ones the shipped reader holds rather than a copy typed
 * into a document.
 *
 * The last group is what makes "a destruction receipt verifies offline" checkable rather than promised. The
 * keys are rebuilt from the labels the file publishes, which is all the generator had, and the honest row is
 * re-signed from the manifest its own bytes carry: the bytes come back identical, so a reviewer holding the
 * published format and no code of ours arrives at the same document.
 */

const file = loadDestructionReceiptVectors();
const ERROR_DOC = fileURLToPath(new URL('../../../docs/error-codes.md', import.meta.url));

/** The one derivation the generator uses, restated here rather than imported, so the suite proves the label. */
function labeled(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

const KEYS = new Map(file.layout.signingKeys.map((one) => [one.role, signingKeyFromSeed(labeled(one.label))]));
for (const [role, key] of KEYS) {
  const stated = file.layout.signingKeys.find((one) => one.role === role)!.kid;
  if (toHex(key.kid) !== stated) throw new Error(`the published kid for ${role} is not sha256 of its label's key`);
}
const SIGNER = KEYS.get('signer')!;

function bytesOf(one: { name: string; documentBase64Url?: string }): Uint8Array {
  if (one.documentBase64Url === undefined) throw new Error(`${one.name} publishes no document to read`);
  return fromBase64Url(one.documentBase64Url);
}

function codeOf(run: () => unknown): string {
  try {
    run();
    return 'verify-ok';
  } catch (reason) {
    return reason instanceof ReceiptError ? reason.code : `UNCODED ${String(reason)}`;
  }
}

function structuralOf(one: { name: string; documentBase64Url?: string }): string {
  return codeOf(() => decodeDestructionReceipt(bytesOf(one)));
}

function verificationOptions(input: DestructionReceiptVerificationInput) {
  if (input.key !== null && !KEYS.has(input.key)) throw new Error(`unknown verification key: ${String(input.key)}`);
  return {
    ...(input.key === null ? {} : { publicKey: KEYS.get(input.key)!.publicKey }),
    ...(input.objectBase64Url === null ? {} : { objectBytes: fromBase64Url(input.objectBase64Url) }),
  };
}

function verdictOf(one: (typeof file.vectors)[number]): string {
  if (one.verification === null) throw new Error(`${one.name} publishes no verification input`);
  const options = verificationOptions(one.verification);
  return codeOf(() => verifyDestructionReceipt(bytesOf(one), options));
}

const ACCEPTANCES = file.vectors.filter((one) => one.arm === 'accept');
const REFUSALS = file.vectors.filter((one) => one.arm === 'refuse');
const WITH_DOCUMENT = file.vectors.filter((one) => one.documentBase64Url !== undefined);
const READABLE = WITH_DOCUMENT.filter((one) => one.structural === 'verify-ok');

describe('the published destruction receipt suite', () => {
  it('states one version, and it is the one the format declares', () => {
    expect(file.version).toBe(1);
    expect(file.layout.versions).toEqual([1]);
    expect(file.layout.document).toBe(DESTRUCTION_RECEIPT_CONTENT_TYPE);
  });

  it('names the same registries the shipped reader holds', () => {
    expect(file.layout.manifestMembers).toEqual([...DESTRUCTION_RECEIPT_MANIFEST_MEMBERS]);
    expect(file.layout.entryMembers).toEqual([...DESTRUCTION_RECEIPT_ENTRY_MEMBERS]);
    expect(file.layout.copyClasses).toEqual([...DESTRUCTION_COPY_CLASSES]);
    expect(file.layout.unreachableClasses).toEqual([...DESTRUCTION_UNREACHABLE_COPY_CLASSES]);
    expect(file.layout.objectKinds).toEqual([...DESTRUCTION_OBJECT_KINDS]);
  });

  it('carries 34 cases: four acceptances and thirty refusals, including two writer-only cases', () => {
    expect(file.vectors).toHaveLength(34);
    expect(ACCEPTANCES).toHaveLength(4);
    expect(REFUSALS).toHaveLength(30);
    expect(WITH_DOCUMENT).toHaveLength(32);
    const writerOnly = file.vectors.filter((one) => one.documentBase64Url === undefined);
    expect(writerOnly.map((one) => one.name)).toEqual(['writer-refuses-to-sign-overreach', 'writer-refuses-its-own-refusal']);
    for (const one of writerOnly) expect(one.verification).toBeNull();
    expect(new Set(REFUSALS.map((one) => one.expected)).size, 'the refusals turn on too few distinct rules').toBeGreaterThanOrEqual(6);
  });

  it('does not change the verification verdict when only expected is changed', () => {
    for (const one of WITH_DOCUMENT) {
      expect(one.verification).not.toBeNull();
      const options = verificationOptions(one.verification!);
      const actual = verdictOf(one);
      for (const expected of ['verify-ok', 'DESTRUCTION_RECEIPT_UNKNOWN_KEY', 'DESTRUCTION_RECEIPT_KID_MISMATCH']) {
        const changed = { ...one, expected };
        expect(verificationOptions(changed.verification!), `${one.name}: expected changed the arguments`).toEqual(options);
        expect(verdictOf(changed), `${one.name}: expected changed the verdict`).toBe(actual);
      }
    }
  });

  it('answers every row with the verdict the row states, at both doors', () => {
    for (const one of WITH_DOCUMENT) {
      expect(structuralOf(one), `${one.name}: the structural door disagrees with the published verdict`).toBe(one.structural);
      expect(verdictOf(one), `${one.name}: the verifying door disagrees with the published verdict`).toBe(one.expected);
    }
  });

  it.each([
    ['malformed-cbor', 'DESTRUCTION_RECEIPT_MALFORMED_CBOR'],
    ['empty-states', 'DESTRUCTION_RECEIPT_BAD_MANIFEST'],
    ['states-over-byte-limit', 'DESTRUCTION_RECEIPT_BAD_MANIFEST'],
  ])('publishes and replays %s', (name, code) => {
    const one = file.vectors.find((row) => row.name === name)!;
    expect(one).toBeDefined();
    expect(one.verification).toEqual({ key: 'signer', objectBase64Url: null });
    expect(one.structural).toBe(code);
    expect(one.expected).toBe(code);
    expect(structuralOf(one)).toBe(code);
    expect(verdictOf(one)).toBe(code);
    if (name !== 'malformed-cbor') {
      const envelope = decodeCanonical(bytesOf(one)) as unknown as { contents: Uint8Array[] };
      const payload = decodeCanonical(envelope.contents[2]!) as Map<string, unknown>;
      const states = payload.get('states') as string;
      expect(new TextEncoder().encode(states).length).toBe(name === 'empty-states' ? 0 : 2049);
      expect(states.length).toBeLessThan(2048);
    }
  });

  it('publishes a structurally valid receipt with a corrupted signature under the correct key', () => {
    const one = file.vectors.find((row) => row.name === 'signature-corrupted')!;
    expect(one).toBeDefined();
    expect(one.verification).toEqual({ key: 'signer', objectBase64Url: null });
    expect(one.structural).toBe('verify-ok');
    expect(one.expected).toBe('INVALID_SIGNATURE');
    const honest = decodeDestructionReceipt(bytesOf(ACCEPTANCES[0]!));
    const corrupted = decodeDestructionReceipt(bytesOf(one));
    expect(corrupted.envelope.protectedBytes).toEqual(honest.envelope.protectedBytes);
    expect(corrupted.envelope.payloadBytes).toEqual(honest.envelope.payloadBytes);
    expect(corrupted.envelope.signature).not.toEqual(honest.envelope.signature);
    expect(verdictOf(one)).toBe('INVALID_SIGNATURE');
  });

  it('keeps the two doors apart where a document is whole and only a key, signature or object refuses it', () => {
    // A row that reads as a document and fails only against a key or against bytes a caller holds is the pair
    // this suite exists to publish: a port that answered `verify-ok` from the shape alone is caught here.
    const apart = file.vectors.filter((one) => one.structural === 'verify-ok' && one.expected !== 'verify-ok');
    expect(apart.length).toBeGreaterThanOrEqual(3);
    for (const one of apart) {
      expect(one.arm).toBe('refuse');
      expect(['DESTRUCTION_RECEIPT_KID_MISMATCH', 'DESTRUCTION_RECEIPT_UNKNOWN_KEY', 'DESTRUCTION_RECEIPT_OBJECT_MISMATCH', 'DESTRUCTION_RECEIPT_KIND_DISAGREES', 'INVALID_SIGNATURE']).toContain(one.expected);
    }
  });

  it('omits backup, and only backup, in class-left-unstated', () => {
    const one = file.vectors.find((row) => row.name === 'class-left-unstated')!;
    const envelope = decodeCanonical(bytesOf(one)) as unknown as { contents: Uint8Array[] };
    const payload = decodeCanonical(envelope.contents[2]!) as Map<string, unknown>;
    const reach = payload.get('reach') as Map<string, unknown>[];
    expect(reach.map((entry) => entry.get('class'))).toEqual(['store', 'pack', 'export', 'handout']);
    expect(structuralOf(one)).toBe('DESTRUCTION_RECEIPT_MISSING_COPY_CLASS');
  });

  it('states a reach for every copy class on every accepted row, and none beyond the format at the class that is out of reach', () => {
    for (const one of ACCEPTANCES) {
      const manifest = decodeDestructionReceipt(bytesOf(one)).manifest;
      expect(manifest.reach.map((each) => each.class)).toEqual([...DESTRUCTION_COPY_CLASSES]);
      for (const unreachable of DESTRUCTION_UNREACHABLE_COPY_CLASSES) {
        expect(
          manifest.reach.find((each) => each.class === unreachable)?.outcome,
          `${one.name} claims reach over ${unreachable}`,
        ).toBe(file.layout.reachOutcomes.notReached);
      }
    }
  });

  it('uses digest widths in readable rows and contains none of the known test public keys verbatim', () => {
    // These fixture-specific byte comparisons are not a general key-material detector.
    for (const one of READABLE) {
      const manifest = decodeDestructionReceipt(bytesOf(one)).manifest;
      expect(manifest.object).toHaveLength(32);
      expect(manifest.key).toHaveLength(32);
    }
    for (const one of WITH_DOCUMENT) {
      const raw = Buffer.from(bytesOf(one));
      for (const key of KEYS.values()) {
        expect(raw.includes(Buffer.from(key.publicKey)), `${one.name} carries a public key in its bytes`).toBe(false);
      }
    }
  });

  it('re-signs the honest document from the labels the file publishes and gets the same bytes back', () => {
    const first = ACCEPTANCES[0]!;
    const manifest = decodeDestructionReceipt(bytesOf(first)).manifest;
    expect(toHex(manifest.key)).toBe(file.layout.signingKeys.find((one) => one.role === 'destroyed')!.kid);
    expect(toHex(signDestructionReceipt(manifest, SIGNER))).toBe(toHex(bytesOf(first)));
  });

  it('names every code it refuses with, in the error-code document', () => {
    const document = readFileSync(ERROR_DOC, 'utf8');
    const codes = new Set([...document.matchAll(/^\| `([A-Z0-9_]+)` \| `ReceiptErrorCode`/gmu)].map((found) => found[1]!));
    for (const one of REFUSALS) {
      expect(codes.has(one.expected), `${one.name} refuses with ${one.expected}, which error-codes.md does not row`).toBe(true);
    }
  });
});
