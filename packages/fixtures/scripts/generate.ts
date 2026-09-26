import { sha256 } from '@noble/hashes/sha2.js';
import {
  issueReceipt,
  receiptToJson,
  decodeReceipt,
  encodePayload,
  signCoseSign1,
  type ReceiptPayloadV2,
} from '@ashaveri/receipt';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { labeled } from './seed.ts';
import { markedBuffered } from './marking-shapes.ts';
import { fixtureKey, fixturePayload } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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

  /**
   * A marked v2 receipt over the same bytes `marking-v1.json` publishes for the buffered shape, so the
   * two suites check each other: `res` is sha256 of the whole response and `mk.d` is sha256 of the one
   * member inside it, and a port that gets either span wrong disagrees with one file or the other.
   * Nothing here invents a third spelling of the mark: the response and its region come from the same
   * builder the vector generator uses.
   */
  const markedResponse = markedBuffered();
  const markedPayload: ReceiptPayloadV2 = {
    ...fixturePayload({ res: sha256(new TextEncoder().encode(markedResponse.response)) }),
    v: 2,
    mk: { sch: 'provenance-v1', d: sha256(new TextEncoder().encode(markedResponse.region)) },
  };
  const markedBytes = issueReceipt(markedPayload, key);

  const vectors: Array<{ name: string; bytes: Uint8Array; expected: string; twin: boolean; note?: string }> = [
    { name: 'receipt-valid-v1', bytes: validBytes, expected: 'verify-ok', twin: true },
    { name: 'receipt-software-v1', bytes: softwareBytes, expected: 'verify-ok', twin: true },
    {
      name: 'receipt-marked-v2',
      bytes: markedBytes,
      expected: 'verify-ok',
      twin: true,
      note: 'A v2 receipt carrying `mk`: its `res` is sha256 of the marked buffered response and its `mk.d` is sha256 of the one marking member inside those same bytes, both the bytes marking-v1.json publishes for the buffered shape.',
    },
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
