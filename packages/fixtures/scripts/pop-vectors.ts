import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EMPTY_BODY_SHA256_HEX,
  fromBase64Url,
  POP_AUTH_PREFIX,
  POP_NONCE_BYTES,
  POP_SCHEME,
  POP_TIMESTAMP_TOLERANCE_SECONDS,
  parsePopAuthorization,
  popSigningString,
  ReceiptError,
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

/**
 * A header or a signing attempt that is nearly right, beside the refusal the shipped code answers it
 * with.
 *
 * The accepted vectors above show a port what to send; these show it what to refuse, which is the half
 * a second implementation agrees on far more often than it should. Each row is built out of one of the
 * vectors above rather than written out by hand, so what makes it wrong is one named edit to bytes this
 * file already publishes, and each row's code is the one the package's own parser or signer threw when
 * this script ran, not a guess at what it would say.
 */
interface RefusalCase {
  readonly name: string;
  readonly note: string;
  /** The accepted vector this near miss is one edit of. */
  readonly vector: string;
  /** Which shipped step answers it: the signer, before a header exists, or the parser, after one does. */
  readonly stage: 'sign' | 'parse';
  /** How many trailing characters of the signature parameter are taken off, for a `parse` row. */
  readonly truncateSignatureBy?: number;
  /** The nonce width presented, for a `sign` row that gets it wrong. */
  readonly nonceBytes?: number;
  /** The scheme token spelled as though it named another version. */
  readonly schemeToken?: string;
}

const REFUSALS: readonly RefusalCase[] = [
  {
    name: 'signature-two-characters-short',
    note: 'The completion authorization with the last two characters of its `sig` parameter taken off, which is sixty-three bytes of signature rather than sixty-four. It is a whole header that parses, and the width is the only thing wrong with it.',
    vector: 'completion-post',
    stage: 'parse',
    truncateSignatureBy: 2,
  },
  {
    name: 'scheme-token-naming-another-version',
    note: 'The same header opening on `Ashaveri-PoPv2` instead of `Ashaveri-PoP`. Every parameter is intact and the signature is the right length: what is missing is any claim this scheme can check, so the refusal has to be about the scheme and not about the bytes.',
    vector: 'completion-post',
    stage: 'parse',
    schemeToken: `${POP_AUTH_PREFIX}v2`,
  },
  {
    name: 'nonce-one-byte-short',
    note: 'The completion fields with a fifteen-byte nonce in place of the sixteen the scheme names. Nothing is signed, because the width is refused before the signing string is built: a client that paid for a signature and then heard about its nonce would be told the wrong thing about the wrong step.',
    vector: 'completion-post',
    stage: 'sign',
    nonceBytes: POP_NONCE_BYTES - 1,
  },
];

/** What one refusal row presents, and which shipped step is asked about it. */
interface Presented {
  readonly fields: PopFields;
  readonly header: string;
}

/**
 * The fields and the header a row presents, derived from the accepted vector it is one edit of. A nonce
 * is changed where the row is about a nonce; a header is changed where the row is about a header, and
 * the signing string published beside it stays the one the signature covers, because that is the fact a
 * reader checks the header against.
 */
function present(row: RefusalCase, base: (typeof vectors)[number]): Presented {
  const fields: PopFields = {
    ts: base.fields.ts,
    nonce:
      row.nonceBytes === undefined
        ? fromBase64Url(base.fields.nonce)
        : labeled(`${KEY_ID}/nonce/${row.name}`, row.nonceBytes),
    method: base.fields.method,
    target: base.fields.target,
    bodyDigestHex: base.fields.bodyDigestHex,
  };
  let header = base.authorization;
  if (row.truncateSignatureBy !== undefined) {
    const at = base.authorization.lastIndexOf('sig=');
    header = `${base.authorization.slice(0, at + 4)}${base.authorization.slice(at + 4, -row.truncateSignatureBy)}`;
  } else if (row.schemeToken !== undefined) {
    header = `${row.schemeToken}${base.authorization.slice(POP_AUTH_PREFIX.length)}`;
  }
  // A row that states an edit has to make one, or it publishes an accepted vector under a refusal's
  // name and the code below would be the code for nothing.
  if (row.stage === 'parse' && header === base.authorization) {
    throw new Error(`${row.name}: the edit this row states changed nothing in the header`);
  }
  return { fields, header };
}

/** The code the shipped step answers a row with, read off that step rather than asserted. */
function observedCode(row: RefusalCase, presented: Presented): string {
  try {
    if (row.stage === 'sign') {
      signPopAuthorization(presented.fields, KEY_ID, KEY.privateKey);
    } else {
      parsePopAuthorization(presented.header);
    }
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`${row.name}: the shipped step refused with something other than a coded error`);
  }
  throw new Error(`${row.name}: published as a refusal and answered without refusing`);
}

function refusalRow(row: RefusalCase): Record<string, unknown> {
  const base = vectors.find((each) => each.name === row.vector);
  if (base === undefined) throw new Error(`pop-v1.json publishes no vector named ${row.vector}`);
  const presented = present(row, base);
  return {
    name: row.name,
    note: row.note,
    vector: row.vector,
    stage: row.stage,
    fields: { ...base.fields, nonce: toBase64Url(presented.fields.nonce) },
    signingString: row.stage === 'sign' ? popSigningString(presented.fields) : base.signingString,
    authorization: presented.header,
    code: observedCode(row, presented),
  };
}

const refusals = REFUSALS.map(refusalRow);

writeFileSync(
  join(DATA, 'pop-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        `TEST ONLY. The private key in this file is a published wire-format vector, generated from a fixed seed so every language can reproduce every signature. It protects nothing and must never be used to sign a real request. Every vector also carries the same fixed ts, which is a reproducibility value and not a plausible request time: it sits outside the ${POP_TIMESTAMP_TOLERANCE_SECONDS}-second freshness window, so a verifier that applies that window as well as checking the signature refuses these authorizations on the timestamp alone, while the signature over the published signing string verifies. \`refusals\` are near misses built out of the vectors above, each carrying the code the shipped signer or parser answers it with.`,
      scheme: POP_SCHEME,
      separator: '\n',
      emptyBodySha256Hex: EMPTY_BODY_SHA256_HEX,
      key: {
        id: KEY_ID,
        privateKeyHex: toHex(KEY.privateKey),
        publicKeyHex: toHex(KEY.publicKey),
      },
      vectors,
      refusals,
    },
    null,
    2,
  )}\n`,
);

console.log(`${join(DATA, 'pop-v1.json')}: ${String(vectors.length)} vectors, ${String(refusals.length)} refusals`);

