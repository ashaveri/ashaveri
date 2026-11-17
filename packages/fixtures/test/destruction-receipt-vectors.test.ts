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
  decodeDestructionReceipt,
  fromBase64Url,
  signDestructionReceipt,
  signingKeyFromSeed,
  toHex,
  verifyDestructionReceipt,
} from '@ashaveri/receipt';
import { loadDestructionReceiptVectors } from '../src/index.js';

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

function verdictOf(one: (typeof file.vectors)[number]): string {
  if (one.expected === 'DESTRUCTION_RECEIPT_UNKNOWN_KEY') return codeOf(() => verifyDestructionReceipt(bytesOf(one), {}));
  const objectBytes = one.objectBase64Url === undefined ? undefined : fromBase64Url(one.objectBase64Url);
  const handedKey = one.expected === 'DESTRUCTION_RECEIPT_KID_MISMATCH' ? KEYS.get('another-callers-key')!.publicKey : SIGNER.publicKey;
  return codeOf(() =>
    verifyDestructionReceipt(bytesOf(one), {
      publicKey: handedKey,
      ...(objectBytes === undefined ? {} : { objectBytes }),
    }),
  );
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

  it('carries both arms, and neither is empty', () => {
    expect(ACCEPTANCES.length, 'the suite publishes no accepted receipt').toBeGreaterThan(0);
    expect(REFUSALS.length, 'the suite publishes no refused receipt').toBeGreaterThan(0);
    expect(new Set(REFUSALS.map((one) => one.expected)).size, 'the refusals turn on too few distinct rules').toBeGreaterThanOrEqual(6);
  });

  it('answers every row with the verdict the row states, at both doors', () => {
    for (const one of WITH_DOCUMENT) {
      expect(structuralOf(one), `${one.name}: the structural door disagrees with the published verdict`).toBe(one.structural);
      expect(verdictOf(one), `${one.name}: the verifying door disagrees with the published verdict`).toBe(one.expected);
    }
  });

  it('keeps the two doors apart where a document is whole and only a key or an object refuses it', () => {
    // A row that reads as a document and fails only against a key or against bytes a caller holds is the pair
    // this suite exists to publish: a port that answered `verify-ok` from the shape alone is caught here.
    const apart = file.vectors.filter((one) => one.structural === 'verify-ok' && one.expected !== 'verify-ok');
    expect(apart.length).toBeGreaterThanOrEqual(3);
    for (const one of apart) {
      expect(one.arm).toBe('refuse');
      expect(['DESTRUCTION_RECEIPT_KID_MISMATCH', 'DESTRUCTION_RECEIPT_UNKNOWN_KEY', 'DESTRUCTION_RECEIPT_OBJECT_MISMATCH', 'DESTRUCTION_RECEIPT_KIND_DISAGREES']).toContain(one.expected);
    }
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

  it('carries no key material in any published document, only the kid the format names', () => {
    // The widths belong to the documents a reader opens; the byte scan asks nothing of a reader, so it runs
    // over every published document, including the ones assembled to be refused.
    for (const one of READABLE) {
      const manifest = decodeDestructionReceipt(bytesOf(one)).manifest;
      expect(manifest.object).toHaveLength(32);
      expect(manifest.key).toHaveLength(32);
    }
    for (const one of WITH_DOCUMENT) {
      const raw = Buffer.from(bytesOf(one));
      for (const key of KEYS.values()) {
        // A public half is 32 bytes of key material by any name, and no published document carries one.
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
