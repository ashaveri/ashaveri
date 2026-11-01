import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeReceipt, toBase64Url, toHex, type Encryption, type ReceiptPayloadV2 } from '@ashaveri/receipt';
import { evidenceReportData } from '@ashaveri/sdk';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The challenge a receipt states, published as arithmetic rather than as a claim.
 *
 * `docs/receipt-spec.md` step 10 says what the value is; a sentence cannot settle an order. The rule folds
 * three parts out of the signed payload — the request nonce `nce`, the session public key `enc.pk`, and the
 * request digest `req` — into `sha256(nce || pk || req)`, and a second implementation can agree with this
 * one on every member, every width and every label while concatenating them the other way round. No
 * signature test catches that, because both readings produce a well-formed 32-byte digest and only one of
 * them is what the hardware was asked to quote. So the pre-image itself is published as bytes, beside the
 * digest it hashes to, for each arm the format states.
 *
 * The triples are not invented here. Each row reads its nonce, its request digest and its key out of a
 * receipt this package already publishes and signs (`data/manifest.json` names the row, `data/receipts/`
 * holds its bytes), so the published arithmetic is about a document an auditor can be handed, and the two
 * files check each other: a generator that drifted on either side disagrees here rather than silently.
 *
 * The expected digest is computed twice before it is written: once by `evidenceReportData` in
 * `@ashaveri/sdk`, which is the derivation the shipped client runs, and once by concatenation in this file,
 * which is the reading an implementation without our code has to match. A row whose two answers differ stops
 * this run, so the published value cannot be one of them by accident.
 */

/** The receipt rows this suite reads its triples out of, one per arm the format states. */
const SOURCES = [
  {
    name: 'plain-arm',
    document: 'manifest.json#receipt-enc-plain-v2',
    note: 'The document whose `enc` states that both legs rode the wire in the clear. There is no key in it to fold, so the value a platform quote is bound to is `sha256(nce || req)` and it is byte for byte what this rule shipped before a key existed to fold: the plain arm is not a third reading, it is the old one, and a row that moved it would move every receipt served under it.',
  },
  {
    name: 'session-arm',
    document: 'manifest.json#receipt-enc-session-v2',
    note: 'The document whose `enc` names a session key. The same `nce` and `req` as the plain row above, and one more part between them, so the two rows differ by the arm alone and a reader that folded a key where the document names none, or named one where the document folds it, produces the other row value and is refused. The key is a fixture value this corpus derives from its own seed and no party holds it: the row pins the arithmetic over the bytes a receipt states, not a secret behind them.',
  },
] as const;

interface Row {
  readonly name: string;
  readonly note: string;
  readonly document: string;
  readonly arm: string;
  readonly parts: readonly string[];
  readonly nonceBase64Url: string;
  readonly sessionKeyBase64Url?: string;
  readonly requestDigestHex: string;
  readonly preImageBase64Url: string;
  readonly preImageByteLength: number;
  readonly digestHex: string;
  readonly digestByteLength: number;
}

const manifest = JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as {
  fixtures: Array<{ name: string; path: string; enc?: { sch: string; pkBase64Url?: string } }>;
};

/** The signed document a row names, decoded back to the payload whose members the row publishes. */
function documentPayload(rowName: string): ReceiptPayloadV2 {
  const entry = manifest.fixtures.find((each) => each.name === rowName);
  if (entry === undefined) throw new Error(`data/manifest.json publishes no row named ${rowName}`);
  const bytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
  const decoded = decodeReceipt(bytes).payload;
  if (decoded.v !== 2) throw new Error(`${rowName} is not a document that states an encryption arm`);
  return decoded;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const all = new Uint8Array(parts.reduce((total, one) => total + one.length, 0));
  let at = 0;
  for (const part of parts) {
    all.set(part, at);
    at += part.length;
  }
  return all;
}

/**
 * One row: the triple read out of the published document, the pre-image the rule builds from it, and the
 * digest both derivations agree on.
 *
 * The order is written as data in `parts` as well as being the order the bytes below are laid out in, so a
 * reader checking this file checks the stated order against the published concatenation rather than against
 * its own assumption about what `||` means.
 */
function vector(source: (typeof SOURCES)[number]): Row {
  const rowName = source.document.split('#')[1]!;
  const payload = documentPayload(rowName);
  const enc: Encryption = payload.enc;
  const parts = enc.sch === 'none' ? [payload.nce, payload.req] : [payload.nce, enc.pk, payload.req];
  const named = enc.sch === 'none' ? ['nce', 'req'] : ['nce', 'enc.pk', 'req'];
  const preImage = concat(...parts);
  const digest = sha256(preImage);
  const fromTheClient = evidenceReportData(payload.nce, payload.req, enc);
  if (toHex(digest) !== toHex(fromTheClient)) {
    throw new Error(
      `${source.name}: this file's concatenation hashes to ${toHex(digest)} and the shipped derivation gives ` +
        `${toHex(fromTheClient)}, so one of them is wrong and neither may be published`,
    );
  }
  return {
    name: source.name,
    note: source.note,
    document: source.document,
    arm: enc.sch,
    parts: named,
    nonceBase64Url: toBase64Url(payload.nce),
    ...(enc.sch === 'none' ? {} : { sessionKeyBase64Url: toBase64Url(enc.pk) }),
    requestDigestHex: toHex(payload.req),
    preImageBase64Url: toBase64Url(preImage),
    preImageByteLength: preImage.length,
    digestHex: toHex(digest),
    digestByteLength: digest.length,
  };
}

const vectors = SOURCES.map(vector);

/**
 * A reader that applied the other arm's rule, or the right parts in the wrong order, and the answer a
 * conforming client owes it.
 *
 * Each row presents the digest one wrong reading produces for one of the documents above, beside the digest
 * that document states. The three are pairwise distinct for one triple, which is what makes the refusal
 * reachable rather than a coincidence of hashing: no field a platform can quote binds two of these values,
 * so a document minted under one rule is never accepted by a reader on another.
 *
 * The codes are what the receipt-linked path answers, and they are named rather than described because the
 * half a port gets wrong is the answer it gives, not the reason it gives it. A skew never answers
 * `EVIDENCE_NOT_FOUND` on that path: the evidence route mints for any value the caller names instead of
 * looking one up, so the disagreement surfaces at the receipt's own digest commitment
 * (`EVIDENCE_DIGEST_MISMATCH`) or at the binding step over the document the receipt genuinely signed
 * (`EVIDENCE_REPORT_DATA_MISMATCH`). `packages/sdk/test/challenge-vectors.test.ts` replays every row here
 * through the shipped verifier and refuses the file if a stated code is not the code the shipped path gives.
 */
interface Refusal {
  readonly name: string;
  readonly note: string;
  readonly document: string;
  readonly wrongReading: string;
  readonly presentedPreImageBase64Url: string;
  readonly presentedDigestHex: string;
  readonly statedDigestHex: string;
  readonly code: 'EVIDENCE_DIGEST_MISMATCH' | 'EVIDENCE_REPORT_DATA_MISMATCH';
  readonly notCode: 'EVIDENCE_NOT_FOUND';
}

const plain = vectors.find((each) => each.name === 'plain-arm')!;
const session = vectors.find((each) => each.name === 'session-arm')!;
const sessionTriple = documentPayload('receipt-enc-session-v2');
const plainTriple = documentPayload('receipt-enc-plain-v2');

/** The key a published document states in its own arm, read out of the signed bytes rather than repeated here. */
function statedKey(payload: ReceiptPayloadV2): Uint8Array {
  if (payload.enc.sch === 'none') throw new Error('this document states no key, so a row may not publish one');
  return payload.enc.pk;
}

const SESSION_KEY = statedKey(sessionTriple);

/** The digest of one byte string, published beside the string so a reader can recompute rather than trust. */
const digestOf = (preImage: Uint8Array): string => toHex(sha256(preImage));

const REFUSALS: Refusal[] = [
  {
    name: 'session-arm-read-as-plain',
    note: 'The session document above, weighed as though its arm named no key: the reader hashes `nce || req` and asks the route with that. The deployment minted its evidence for the composite, so the bytes handed back are not the document the receipt digests into `att.d`, and the refusal is the receipt speaking rather than the platform.',
    document: 'manifest.json#receipt-enc-session-v2',
    wrongReading: 'sha256(nce || req) over a document whose `enc` names a key',
    presentedPreImageBase64Url: toBase64Url(concat(sessionTriple.nce, sessionTriple.req)),
    presentedDigestHex: digestOf(concat(sessionTriple.nce, sessionTriple.req)),
    statedDigestHex: session.digestHex,
    code: 'EVIDENCE_DIGEST_MISMATCH',
    notCode: 'EVIDENCE_NOT_FOUND',
  },
  {
    name: 'plain-arm-folded-a-key',
    note: 'The plain document above, weighed as though its arm named a key, with the attestation digest `att.d` put where the key would go because the reader wanted three parts and the payload offers one beside the nonce. Nothing about this is a well-formed reading of the format: the arm states that no key was exchanged, so there is no part to insert, and a reader that inserted something anyway asks for an evidence document no receipt of this deployment commits to.',
    document: 'manifest.json#receipt-enc-plain-v2',
    wrongReading: 'sha256(nce || att.d || req) over a document whose `enc` states `none`',
    presentedPreImageBase64Url: toBase64Url(concat(plainTriple.nce, plainTriple.att.d, plainTriple.req)),
    presentedDigestHex: digestOf(concat(plainTriple.nce, plainTriple.att.d, plainTriple.req)),
    statedDigestHex: plain.digestHex,
    code: 'EVIDENCE_DIGEST_MISMATCH',
    notCode: 'EVIDENCE_NOT_FOUND',
  },
  {
    name: 'parts-in-another-order',
    note: 'The three members of the session triple, right and concatenated request-last instead of request-middle: `sha256(nce || req || pk)`. This row exists because the members and the widths are identical to the accepted reading and only their order differs, which is exactly the disagreement a signature cannot see and a vector can: a quote whose field carries this value binds nothing a client on the stated order asked it to bind.',
    document: 'manifest.json#receipt-enc-session-v2',
    wrongReading: 'sha256(nce || req || pk), the stated members in another order',
    presentedPreImageBase64Url: toBase64Url(concat(sessionTriple.nce, sessionTriple.req, SESSION_KEY)),
    presentedDigestHex: digestOf(concat(sessionTriple.nce, sessionTriple.req, SESSION_KEY)),
    statedDigestHex: session.digestHex,
    code: 'EVIDENCE_REPORT_DATA_MISMATCH',
    notCode: 'EVIDENCE_NOT_FOUND',
  },
];

/**
 * A refusal is only a refusal if the presented value differs from the value the document states, and the
 * three readings of one triple are pairwise distinct: a collision would publish a row that any reader
 * satisfies by accident. The check is over the published hex, because that is what a port compares.
 */
for (const each of REFUSALS) {
  if (each.presentedDigestHex === each.statedDigestHex) {
    throw new Error(`${each.name} presents the value it states, so it refuses nothing`);
  }
}
const sessionReadings = new Set([
  session.digestHex,
  ...REFUSALS.filter((each) => each.document === session.document).map((each) => each.presentedDigestHex),
]);
if (sessionReadings.size !== 1 + REFUSALS.filter((each) => each.document === session.document).length) {
  throw new Error('the session rows do not state pairwise distinct readings of one triple');
}

writeFileSync(
  join(DATA, 'challenge-v1.json'),
  `${JSON.stringify(
    {
      version: 1,
      description:
        'The attestation challenge a receipt states, published as the bytes it hashes and the digest they give. Where a receipt\'s `enc` names a session arm, the value a platform quote must be bound to is sha256(nce || pk || req): the request nonce, the session public key the signed payload itself carries, and the digest of the exact request bytes, concatenated in that order and no other. Where `enc` states the plain arm, or the document is a version that names no arm, there is no key to fold and the value is sha256(nce || req), unchanged from what shipped. The arm the document states selects the rule, so no member names a ceremony and no new label exists for this: the registry and the member lists are untouched. Every triple is read out of a receipt this package publishes and signs, the pre-image is published as bytes because part order is a wire fact a sentence cannot pin, and each expected digest was computed twice before it was written — once by the shipped client derivation and once by concatenation here. `refusals` are the near readings: the other arm\'s rule over one of these documents, a key folded where the arm names none, and the same members in another order, each with the code the receipt-linked path owes it. What this suite does NOT pin is the platform\'s seal: no quote captured in this repository carries a composite, because a captured report data is fixed by the signature over it, so these rows pin the arithmetic and the owed second capture is stated in `layout.owedPlatformCapture` and in `docs/vectors.md` rather than left implied.',
      layout: {
        format: 'one challenge rule, two arms, stated as pre-image bytes and the digest they hash to',
        twin: 'the receipts this suite reads its triples out of are published and signed by generate.ts in data/manifest.json and data/receipts/',
        reader:
          'evidenceReportData in @ashaveri/sdk is the shipped derivation, and the pre-image published beside each digest is what an implementation with none of our code has to concatenate',
        arms: ['none', 'x25519-aes-256-gcm-v1'],
        partOrder:
          'the session arm is nce, then enc.pk, then req, and the plain arm is nce then req; the `parts` column states the order and the `preImageBase64Url` bytes are laid out in it, so a reader checks the order against the bytes rather than against its assumption',
        challengeNonceIsNotTheSealNonce:
          'nce is the request\'s challenge nonce, the value the platform is asked to quote; the AES-256-GCM nonce the session arm seals each leg with is a different value, never folded into this digest and never interchangeable with it',
        encodings: 'byte strings unpadded base64url, digests lowercase hex, lengths in bytes',
        owedPlatformCapture:
          'A vector over a real platform quote whose report data carries a composite is owed to a capture. The Intel-signed quote under attest-core/test/fixtures has its REPORT_DATA fixed by Intel\'s own signature, so no test in this repository can ask it to carry sha256(nce || pk || req); these rows pin the arithmetic and the refusals name the codes, and the platform leg of the rule is witnessed when the confidential-VM lane captures a quote over a composite.',
        verdictFields: [
          'arm',
          'parts',
          'nonceBase64Url',
          'sessionKeyBase64Url',
          'requestDigestHex',
          'preImageBase64Url',
          'preImageByteLength',
          'digestHex',
          'digestByteLength',
        ],
        rowNamingFields: ['name', 'note', 'document'],
      },
      vectors,
      refusals: REFUSALS,
    },
    null,
    2,
  )}\n`,
);

console.log(
  `${join(DATA, 'challenge-v1.json')}: ${String(vectors.length)} vectors, ${String(REFUSALS.length)} refusals`,
);
