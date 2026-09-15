import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_SCHEME,
  popSigningString,
  sha256Hex,
  signPopAuthorization,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');
const KEY_ID = 'pop-vector-key-v1';

/** Deterministic key and nonces, so regenerating the file changes nothing. */
function labeled(label: string, length?: number): Uint8Array {
  const digest = sha256(new TextEncoder().encode(label));
  return length === undefined ? digest : digest.slice(0, length);
}

const PRIVATE_KEY = labeled(`${KEY_ID}/private`);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const FIXED_TS = 1_772_000_000;
const NONCE = labeled(`${KEY_ID}/nonce`, 16);

const BODY = '{"model":"meta-llama/Llama-3.1-8B-Instruct","messages":[{"role":"user","content":"hello"}]}';

interface Case {
  readonly name: string;
  readonly note: string;
  readonly method: string;
  readonly target: string;
  readonly body: string;
}

const CASES: readonly Case[] = [
  {
    name: 'completion-post',
    note: 'A buffered completion. The body digest equals the req field of the receipt for the same request bytes.',
    method: 'POST',
    target: '/v1/chat/completions',
    body: BODY,
  },
  {
    name: 'streaming-post',
    note: 'Identical to a buffered completion at the signing layer: the PoP covers the request, never the response.',
    method: 'POST',
    target: '/v1/chat/completions',
    body: '{"model":"meta-llama/Llama-3.1-8B-Instruct","messages":[{"role":"user","content":"hello"}],"stream":true}',
  },
  {
    name: 'manifest-get',
    note: 'A bodyless route signs the empty-body digest, stated here so a client author does not guess.',
    method: 'GET',
    target: '/v1/deployment-manifest',
    body: '',
  },
  {
    name: 'attestation-get',
    note: 'The request target is signed whole, query included, because for this route the query is the request.',
    method: 'GET',
    target: `/v1/attestation?report_data=${'ab'.repeat(32)}`,
    body: '',
  },
];

const vectors = CASES.map((each) => {
  const bodyBytes = new TextEncoder().encode(each.body);
  const fields: PopFields = {
    ts: FIXED_TS,
    nonce: NONCE,
    method: each.method,
    target: each.target,
    bodyDigestHex: sha256Hex(bodyBytes),
  };
  return {
    name: each.name,
    note: each.note,
    fields: {
      ts: fields.ts,
      nonce: toBase64Url(NONCE),
      method: fields.method,
      target: fields.target,
      bodyBase64Url: toBase64Url(bodyBytes),
      bodyDigestHex: fields.bodyDigestHex,
    },
    signingString: popSigningString(fields),
    authorization: signPopAuthorization(fields, KEY_ID, PRIVATE_KEY),
  };
});

writeFileSync(
  join(DATA, 'pop-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        'TEST ONLY. The private key in this file is a published wire-format vector, generated from a fixed seed so every language can reproduce every signature. It protects nothing and must never be used to sign a real request.',
      scheme: POP_SCHEME,
      separator: '\n',
      emptyBodySha256Hex: EMPTY_BODY_SHA256_HEX,
      key: {
        id: KEY_ID,
        privateKeyHex: Array.from(PRIVATE_KEY, (b) => b.toString(16).padStart(2, '0')).join(''),
        publicKeyHex: Array.from(PUBLIC_KEY, (b) => b.toString(16).padStart(2, '0')).join(''),
      },
      vectors,
    },
    null,
    2,
  )}\n`,
);

console.log(`${join(DATA, 'pop-v1.json')}: ${String(vectors.length)} vectors`);
