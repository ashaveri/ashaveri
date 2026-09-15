import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EMPTY_BODY_SHA256_HEX,
  POP_NONCE_BYTES,
  POP_SCHEME,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  popSigningString,
  sha256Hex,
  signPopAuthorization,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  type PopFields,
} from '@ashaveri/receipt';
import { labeled } from './seed.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');
const KEY_ID = 'pop-vector-key-v1';

// Every byte this script publishes comes out of @ashaveri/receipt: the keypair from the
// package's own seed-to-key derivation, which is the one the gateway's signing key goes
// through too, and the hex from the codec's own hex function. A vector is only golden if
// nothing in it re-implements the thing it is meant to check.
const KEY = signingKeyFromSeed(labeled(`${KEY_ID}/private`));

/**
 * A frozen instant, so regenerating the file changes nothing. It is a reproducibility
 * value and not a plausible request time, which the file itself states: the vectors
 * exercise the signature path, never the freshness one.
 */
const FIXED_TS = 1_772_000_000;

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
    note: 'A buffered completion. Its body digest is the req claim a live receipt over these same request bytes would carry.',
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
  // One nonce per case, keyed by the case name so it stays deterministic. A nonce reused
  // across two signed requests is the replay the header exists to catch, and this file is
  // read as an example of what a client should send.
  const nonce = labeled(`${KEY_ID}/nonce/${each.name}`, POP_NONCE_BYTES);
  const fields: PopFields = {
    ts: FIXED_TS,
    nonce,
    method: each.method,
    target: each.target,
    bodyDigestHex: sha256Hex(bodyBytes),
  };
  return {
    name: each.name,
    note: each.note,
    fields: {
      ts: fields.ts,
      nonce: toBase64Url(fields.nonce),
      method: fields.method,
      target: fields.target,
      bodyBase64Url: toBase64Url(bodyBytes),
      bodyDigestHex: fields.bodyDigestHex,
    },
    signingString: popSigningString(fields),
    authorization: signPopAuthorization(fields, KEY_ID, KEY.privateKey),
  };
});

writeFileSync(
  join(DATA, 'pop-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        `TEST ONLY. The private key in this file is a published wire-format vector, generated from a fixed seed so every language can reproduce every signature. It protects nothing and must never be used to sign a real request. Every vector also carries the same fixed ts, which is a reproducibility value and not a plausible request time: it sits outside the ${POP_TIMESTAMP_TOLERANCE_SECONDS}-second freshness window, so a verifier that applies that window as well as checking the signature refuses these authorizations on the timestamp alone, while the signature over the published signing string verifies.`,
      scheme: POP_SCHEME,
      separator: '\n',
      emptyBodySha256Hex: EMPTY_BODY_SHA256_HEX,
      key: {
        id: KEY_ID,
        privateKeyHex: toHex(KEY.privateKey),
        publicKeyHex: toHex(KEY.publicKey),
      },
      vectors,
    },
    null,
    2,
  )}\n`,
);

console.log(`${join(DATA, 'pop-v1.json')}: ${String(vectors.length)} vectors`);
