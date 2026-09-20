import { ed25519 } from '@noble/curves/ed25519';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import {
  issueReceipt,
  receiptToJson,
  decodeReceipt,
  encodePayload,
  signCoseSign1,
  type SigningKey,
  type ReceiptPayloadV1,
} from '@ashaveri/receipt';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { labeled } from './seed.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fixtureKey(): SigningKey {
  const privateKey = labeled('ashaveri-fixtures/receipt-key/v1');
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, kid: sha256(publicKey) };
}

const FIXED_IAT = 1_772_000_000;

/**
 * Every vector this script writes is a v1 receipt, so the helper names that version rather than the
 * union. `v` is pinned in the literal below and an override cannot move a published fixture into a
 * format its bytes never claimed.
 */
function fixturePayload(overrides: Partial<ReceiptPayloadV1> = {}): ReceiptPayloadV1 {
  return {
    v: 1,
    iss: 'dpl-9f2a41c3',
    ins: 'cvm-i-047f2a',
    iat: FIXED_IAT,
    nce: labeled('ashaveri-fixtures/nonce/v1', 16),
    req: labeled('ashaveri-fixtures/request/v1'),
    res: labeled('ashaveri-fixtures/response/v1'),
    mdl: 'meta-llama/Llama-3.1-8B-Instruct',
    wts: labeled('ashaveri-fixtures/manifest/v1'),
    meas: { tee: 'snp+gpucc', m: sha384(new TextEncoder().encode('ashaveri-fixtures/measurement/v1')) },
    att: {
      d: labeled('ashaveri-fixtures/evidence/v1'),
      ts: FIXED_IAT - 60,
      url: 'https://inference.ashaveri.com/v1/attestation',
    },
    epk: 1,
    tok: { p: 128, c: 64 },
    ...overrides,
  };
}

function main() {
  const key = fixtureKey();

  const validBytes = issueReceipt(fixturePayload(), key);
  const softwareBytes = issueReceipt(
    fixturePayload({ meas: { tee: 'software', m: labeled('ashaveri-fixtures/software-measurement/v1') } }),
    key,
  );
  // Signed by hand on purpose: issueReceipt refuses to produce a payload whose measurement
  // contradicts its kind, and an independent implementation still has to catch that itself.
  const mismatchBytes = signCoseSign1(
    encodePayload(fixturePayload({ meas: { tee: 'snp', m: labeled('ashaveri-fixtures/mismatched-measurement/v1') } })),
    key,
  );
  const tampered = new Uint8Array(validBytes);
  tampered[tampered.length - 1]! ^= 0x01;

  const vectors: Array<{ name: string; bytes: Uint8Array; expected: string; twin: boolean; note?: string }> = [
    { name: 'receipt-valid-v1', bytes: validBytes, expected: 'verify-ok', twin: true },
    { name: 'receipt-software-v1', bytes: softwareBytes, expected: 'verify-ok', twin: true },
    {
      name: 'receipt-meas-mismatch-v1',
      bytes: mismatchBytes,
      expected: 'BAD_PAYLOAD',
      twin: false,
      note: 'Signature is valid; the payload claims tee "snp" but carries a 32-byte measurement, which is the software width.',
    },
    { name: 'receipt-tampered-v1', bytes: tampered, expected: 'INVALID_SIGNATURE', twin: false },
  ];

  mkdirSync(join(DATA, 'keys'), { recursive: true });
  mkdirSync(join(DATA, 'receipts'), { recursive: true });

  writeFileSync(
    join(DATA, 'keys', 'receipt-key-v1.json'),
    JSON.stringify(
      {
        description: 'Deterministic Ed25519 signing key for receipt fixtures. TEST ONLY, never use in production.',
        privateKey: toHex(key.privateKey),
        publicKey: toHex(key.publicKey),
        kid: toHex(key.kid),
      },
      null,
      2,
    ) + '\n',
  );

  const manifestFixtures: Array<Record<string, string>> = [];
  for (const vector of vectors) {
    const path = `receipts/${vector.name}.cbor`;
    writeFileSync(join(DATA, path), vector.bytes);
    const digestSha256 = toHex(sha256(vector.bytes));
    if (vector.twin) {
      const decoded = decodeReceipt(vector.bytes);
      const json = receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);
      writeFileSync(
        join(DATA, `receipts/${vector.name}.json`),
        JSON.stringify({ ...json, digestSha256 }, null, 2) + '\n',
      );
    }
    manifestFixtures.push({
      name: vector.name,
      path,
      digestSha256,
      expected: vector.expected,
      ...(vector.note ? { note: vector.note } : {}),
    });
  }

  writeFileSync(
    join(DATA, 'manifest.json'),
    JSON.stringify(
      {
        version: 1,
        generatedBy: 'ashaveri-fixtures generate',
        cddl: 'receipt.cddl @ashaveri/receipt v0.1.0',
        fixtures: manifestFixtures,
      },
      null,
      2,
    ) + '\n',
  );

  for (const entry of manifestFixtures) console.log(`${entry.name}: ${entry.digestSha256}`);
}

main();
