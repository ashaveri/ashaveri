import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeReceipt, fromBase64Url, toHex, type ReceiptPayloadV2 } from '@ashaveri/receipt';
import { DATA, loadChallengeVectors } from '../src/index.js';
import { assertRowRoster } from './doc-contract.js';

const file = loadChallengeVectors();

/**
 * The published challenge family, read back and recomputed.
 *
 * The suite exists because part order is a wire fact that no signature test can catch: two honest
 * implementations can agree on every member, every width and every label and still concatenate the pieces in
 * another order, and both produce a well-formed 32-byte digest. What stops that here is that the pre-image
 * itself is published as bytes, so this test hashes the bytes a reader is handed rather than re-deriving an
 * order from the same prose the generator read.
 *
 * The triples are not this file's either. Each row names a receipt published by `generate.ts`, so every nonce,
 * request digest and key below is taken back out of the signed document it points at: if the vector suite and
 * the receipt family drift apart, one of them disagrees here, which is the point of publishing the pair.
 */

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const all = new Uint8Array(parts.reduce((total, one) => total + one.length, 0));
  let at = 0;
  for (const part of parts) {
    all.set(part, at);
    at += part.length;
  }
  return all;
}

/** The published receipt a row names, decoded back to the payload whose members the row states. */
function payloadOf(reference: string): ReceiptPayloadV2 {
  const [fileNamed, rowName] = reference.split('#');
  if (fileNamed !== 'manifest.json' || rowName === undefined) {
    throw new Error(`${reference} names no receipt this package publishes`);
  }
  const manifest = JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as {
    fixtures: Array<{ name: string; path: string }>;
  };
  const entry = manifest.fixtures.find((each) => each.name === rowName);
  if (entry === undefined) throw new Error(`data/manifest.json publishes no row named ${rowName}`);
  const bytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
  const decoded = decodeReceipt(bytes).payload;
  if (decoded.v !== 2) throw new Error(`${rowName} states no encryption arm to read a key from`);
  return decoded;
}

describe('data/challenge-v1.json', () => {
  it('publishes one row per arm the format states, and declares its own roster', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(0);
    expect(file.vectors.map((each) => each.arm)).toEqual(['none', 'x25519-aes-256-gcm-v1']);
    expect(file.layout.arms).toEqual(['none', 'x25519-aes-256-gcm-v1']);
    assertRowRoster(file, file.layout.rowNamingFields);
  });

  it.each(file.vectors)('$name: the published pre-image hashes to the published digest', (row) => {
    const preImage = fromBase64Url(row.preImageBase64Url);
    expect(preImage).toHaveLength(row.preImageByteLength);
    expect(toHex(sha256(preImage))).toBe(row.digestHex);
    expect(row.digestByteLength).toBe(32);
  });

  it.each(file.vectors)('$name: the pre-image is the stated parts, in the stated order', (row) => {
    const payload = payloadOf(row.document);
    const pieces: Record<string, Uint8Array> = {
      nce: payload.nce,
      req: payload.req,
      ...(payload.enc.sch === 'none' ? {} : { 'enc.pk': payload.enc.pk }),
    };
    expect(row.parts.map((each) => pieces[each]!)).toHaveLength(row.parts.length);
    expect(toHex(concat(...row.parts.map((each) => pieces[each]!)))).toBe(
      toHex(fromBase64Url(row.preImageBase64Url)),
    );
    expect(toHex(payload.nce)).toBe(toHex(fromBase64Url(row.nonceBase64Url)));
    expect(toHex(payload.req)).toBe(row.requestDigestHex);
    if (payload.enc.sch === 'none') {
      expect(row.sessionKeyBase64Url, 'the plain arm states no key to publish').toBeUndefined();
      // The plain arm is the shipped two-part rule unchanged, so a reader that moved it moved every
      // receipt that was served before a session key existed.
      expect(row.digestHex).toBe(toHex(sha256(concat(payload.nce, payload.req))));
    } else {
      expect(toHex(payload.enc.pk)).toBe(toHex(fromBase64Url(row.sessionKeyBase64Url!)));
      expect(row.digestHex).toBe(toHex(sha256(concat(payload.nce, payload.enc.pk, payload.req))));
    }
  });

  it('keeps the two arms apart on one triple', () => {
    // The published pair differs by the arm alone: same nonce, same request digest. A collision between the
    // two readings would make the rule unobservable, and the rows above would still look well-formed.
    const plain = file.vectors.find((each) => each.arm === 'none')!;
    const session = file.vectors.find((each) => each.arm !== 'none')!;
    expect(plain.nonceBase64Url).toBe(session.nonceBase64Url);
    expect(plain.requestDigestHex).toBe(session.requestDigestHex);
    expect(plain.digestHex).not.toBe(session.digestHex);
    expect(plain.preImageByteLength + 32).toBe(session.preImageByteLength);
  });

  it('states each refusal as a value the accepted row does not produce', () => {
    for (const row of file.refusals) {
      const presented = fromBase64Url(row.presentedPreImageBase64Url);
      expect(toHex(sha256(presented))).toBe(row.presentedDigestHex);
      expect(row.presentedDigestHex, `${row.name} presents the value it states`).not.toBe(row.statedDigestHex);
      expect(row.code).toMatch(/^[A-Z][A-Z0-9_]*$/u);
      expect(row.notCode).toBe('EVIDENCE_NOT_FOUND');
    }
    // Distinctness is a fact per document, not across the file: two published receipts that share a nonce and
    // a request digest share the plain reading too, which is why the row for one document is a refusal of the
    // other only when the document it names is the one being weighed.
    for (const row of file.vectors) {
      const readings = new Set([
        row.digestHex,
        ...file.refusals.filter((each) => each.document === row.document).map((each) => each.presentedDigestHex),
      ]);
      expect(
        readings.size,
        `${row.document} states one digest twice, so a row beside it refuses nothing`,
      ).toBe(1 + file.refusals.filter((each) => each.document === row.document).length);
    }
    expect(file.refusals).toHaveLength(3);
  });

  it('states the same arithmetic the receipt manifest publishes for the same document', () => {
    // Two published files carry this rule: the vector family and the row of the receipt whose bytes it reads.
    // They are written by two generators, and the column on the manifest row is laid out there rather than
    // imported from here, so this comparison is the one that says they still mean the same document.
    const manifest = JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as {
      fixtures: Array<{
        name: string;
        challenge?: { rule: string; parts: string[]; preImageBase64Url: string; digestHex: string };
      }>;
    };
    for (const row of file.vectors) {
      const rowName = row.document.split('#')[1]!;
      const entry = manifest.fixtures.find((each) => each.name === rowName);
      expect(entry, `${rowName} is published by no manifest row`).not.toBeUndefined();
      const stated = entry?.challenge;
      expect(stated, `${rowName} states no challenge column`).not.toBeUndefined();
      expect(stated!.digestHex, `${rowName}: the manifest and the vector suite disagree on one digest`).toBe(row.digestHex);
      expect(stated!.preImageBase64Url).toBe(row.preImageBase64Url);
      expect(stated!.parts).toEqual(row.parts);
      expect(stated!.rule).toBe(row.arm === 'none' ? 'sha256(nce || req)' : 'sha256(nce || pk || req)');
    }
    const statedElsewhere = manifest.fixtures.filter((each) => each.challenge !== undefined).map((each) => each.name);
    expect(statedElsewhere, 'the challenge column is stated on rows other than the two arms it decides').toEqual([
      'receipt-enc-plain-v2',
      'receipt-enc-session-v2',
    ]);
  });

  it('names the platform capture it does not pin', () => {
    // The suite pins arithmetic. The seal over a composite is a capture, and a row that quietly omitted that
    // would leave a reader to discover it by being wrong.
    expect(file.layout.owedPlatformCapture).toContain('capture');
    expect(file.layout.challengeNonceIsNotTheSealNonce).toContain('AES-256-GCM');
  });
});
