import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  issueReceipt,
  receiptToJson,
  decodeReceipt,
  type SigningKey,
  type ReceiptPayload,
} from '@ashaveri/receipt';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function labeled(label: string, length?: number): Uint8Array {
  const digest = sha256(new TextEncoder().encode(label));
  return length ? digest.slice(0, length) : digest;
}

function fixtureKey(): SigningKey {
  const privateKey = labeled('ashaveri-fixtures/receipt-key/v1');
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, kid: sha256(publicKey) };
}

const FIXED_IAT = 1_772_000_000;

function fixturePayload(): ReceiptPayload {
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
    meas: { tee: 'snp+h100cc', m: labeled('ashaveri-fixtures/measurement/v1') },
    att: {
      d: labeled('ashaveri-fixtures/evidence/v1'),
      ts: FIXED_IAT - 60,
      url: 'https://inference.ashaveri.com/v1/attestation',
    },
    epk: 1,
    tok: { p: 128, c: 64 },
  };
}

function main() {
  const key = fixtureKey();
  const payload = fixturePayload();
  const receiptBytes = issueReceipt(payload, key);
  const decoded = decodeReceipt(receiptBytes);
  const json = receiptToJson(decoded.payload, decoded.cose.signature, decoded.header.kid);

  const tampered = new Uint8Array(receiptBytes);
  tampered[tampered.length - 1]! ^= 0x01;

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

  writeFileSync(join(DATA, 'receipts', 'receipt-valid-v1.cbor'), receiptBytes);
  writeFileSync(
    join(DATA, 'receipts', 'receipt-valid-v1.json'),
    JSON.stringify({ ...json, digestSha256: toHex(sha256(receiptBytes)) }, null, 2) + '\n',
  );
  writeFileSync(join(DATA, 'receipts', 'receipt-tampered-v1.cbor'), tampered);

  writeFileSync(
    join(DATA, 'manifest.json'),
    JSON.stringify(
      {
        version: 1,
        generatedBy: 'ashaveri-fixtures generate',
        cddl: 'receipt.cddl @ashaveri/receipt v0.1.0',
        fixtures: [
          {
            name: 'receipt-valid-v1',
            path: 'receipts/receipt-valid-v1.cbor',
            digestSha256: toHex(sha256(receiptBytes)),
            expected: 'verify-ok',
          },
          {
            name: 'receipt-tampered-v1',
            path: 'receipts/receipt-tampered-v1.cbor',
            digestSha256: toHex(sha256(tampered)),
            expected: 'INVALID_SIGNATURE',
          },
        ],
      },
      null,
      2,
    ) + '\n',
  );

  console.log(`receipt-valid-v1:  ${toHex(sha256(receiptBytes))}`);
  console.log(`receipt-tampered-v1: ${toHex(sha256(tampered))}`);
}

main();
