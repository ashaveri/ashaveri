import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ALG_EDDSA,
  DEPLOYMENT_MANIFEST_CONTENT_TYPE,
  ReceiptError,
  decodeCanonical,
  decodeCoseSign1,
  decodeSealedDeploymentManifest,
  encodeCanonical,
  exportSigStructure,
  isSealedDeploymentManifest,
  issueReceipt,
  sealDeploymentManifest,
  sealExport,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifySealedDeploymentManifest,
  type SigningKey,
} from '@ashaveri/receipt';
import { labeled } from './seed.ts';
import { FIXED_IAT, fixtureKey, fixturePayload } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The sealed deployment manifest vectors: whole documents in both shapes a deployment serves, the key
 * material a reader designates beside them, and the verdict each one owes.
 *
 * A manifest can arrive signed and a client has three honest things to say about it, so a suite for it
 * has to carry the states rather than only the signature check. Every row publishes the bytes handed to
 * a reader, the policy entries handed with them, the answer the client path gives, and separately the
 * answer the format's own envelope reader gives, because those two layers refuse for different reasons
 * and a port that confuses them will report a designation problem as tampering.
 *
 * Two readers are named by these files and this generator reaches one of them. The envelope belongs to
 * `@ashaveri/receipt`, whose `sealDeploymentManifest` writes these bytes and whose
 * `decodeSealedDeploymentManifest` and `verifySealedDeploymentManifest` read them, and both are run
 * here: the `seal` field of every row is what that reader answered when this file was written, not what
 * anybody expected it to answer. The three-state reading belongs to `readDeploymentManifest` in
 * `@ashaveri/sdk`, which `@ashaveri/fixtures` does not depend on and cannot reach from a script. Its
 * verdicts are therefore stated here as data and held by the client path over this file in
 * `packages/cli/test/vector-conformance.test.ts`, which replays every row through the shipped reader
 * and fails if the stated answer is not the one the client gives.
 *
 * A document meant to be refused is assembled from the container's published pieces. The honest seal
 * comes from `sealDeploymentManifest` and nothing else, and where a row needs bytes that writer will not
 * produce, which is every row whose protected header names something other than the three labels the
 * format declares, the header is encoded by hand, signed over the same `Sig_structure` the writer uses,
 * and assembled by the published tag-18 writer. `main` stops the run when that hand-assembled path
 * diverges by a single byte from `sealDeploymentManifest` for the canonical header, so the fault cases
 * differ from what a deployment signs only in the position their `edited` field names.
 */

/** The three labels `manifest.cddl` declares for a protected header, and no fourth. */
const LABEL_ALG = 1;
const LABEL_TYP = 3;
const LABEL_KID = 4;

const EMPTY = new Uint8Array(0);

/**
 * The keys this suite publishes, in the two roles the format keeps apart.
 *
 * A deployment signs receipts with one key and manifests with another, and the separation is not
 * decoration: the manifest is the document that states which keys sign receipts, so a wrapper verified
 * under a receipt signing key would let one compromised signing key rewrite the rotation record meant to
 * retire it. So the honest rows are sealed by `SIGNER` and their `keys[]` lists `RECEIPT_SIGNER`, which is
 * the committed fixture key this repository already publishes in `data/keys/receipt-key-v1.json`. That
 * makes the cross-container row sharper as well: the receipt handed to the manifest reader is signed by a
 * key the very manifest beside it lists, and both documents verify cleanly under their own keys.
 * `SECOND_SIGNER` is another deployment's manifest key, and `EXTRA_RECEIPT_KEY` a second receipt key that
 * a rotation history can name.
 */
const SIGNER: SigningKey = signingKeyFromSeed(labeled('ashaveri-fixtures/manifest-v1/signer-a'));
const SECOND_SIGNER: SigningKey = signingKeyFromSeed(labeled('ashaveri-fixtures/manifest-v1/signer-b'));
const EXTRA_RECEIPT_KEY: SigningKey = signingKeyFromSeed(labeled('ashaveri-fixtures/manifest-v1/receipt-key-b'));
const RECEIPT_SIGNER: SigningKey = fixtureKey();
const ALL_KEYS: readonly SigningKey[] = [SIGNER, SECOND_SIGNER, RECEIPT_SIGNER, EXTRA_RECEIPT_KEY];
const KEY_BY_KID = new Map(ALL_KEYS.map((one) => [toHex(one.kid), one]));

/** Each key with the seed it comes from and the role it plays, published as the file states them. */
const KEY_MATERIAL: readonly { key: SigningKey; seed: string; role: string }[] = [
  {
    key: SIGNER,
    seed: "sha256 of 'ashaveri-fixtures/manifest-v1/signer-a'",
    role: 'signs the manifests a reader designates',
  },
  {
    key: SECOND_SIGNER,
    seed: "sha256 of 'ashaveri-fixtures/manifest-v1/signer-b'",
    role: 'signs the manifest nobody designated and the seal that names a key it is not',
  },
  {
    key: RECEIPT_SIGNER,
    seed: "sha256 of 'ashaveri-fixtures/receipt-key/v1', the committed fixture receipt key",
    role: 'the key the documents list in keys[], and the one that signed the receipt handed to the manifest reader',
  },
  {
    key: EXTRA_RECEIPT_KEY,
    seed: "sha256 of 'ashaveri-fixtures/manifest-v1/receipt-key-b'",
    role: 'a second receipt key, named by a rotation history or by no document at all',
  },
];

const ISS = 'ashaveri-mock';
const INS = 'mock-instance-1';
/** The instant every published fixture in this repository is issued at, so regenerating changes no byte. */
const NOW = FIXED_IAT;
const EPOCH_ONE_START = 1_700_000_000;

const encodeText = (text: string): Uint8Array => new TextEncoder().encode(text);
const digest = (bytes: Uint8Array): Uint8Array => sha256(bytes);

/** The measurement and model list the honest document carries, widths matching their kinds. */
const MEASUREMENT = { tee: 'software', m: toHex(digest(encodeText('ashaveri-fixtures/manifest-v1/meas'))) };
const MODELS = [{ id: 'mock-model-1', wts: toHex(digest(encodeText('ashaveri-fixtures/manifest-v1/wts'))) }];

interface KeyEntry {
  readonly kid: string;
  readonly alg: 'Ed25519';
  readonly publicKey: string;
  readonly epk?: number;
  readonly validFrom?: number;
}

const entryOf = (key: SigningKey, epoch?: number, validFrom?: number): KeyEntry =>
  epoch === undefined
    ? { kid: toHex(key.kid), alg: 'Ed25519', publicKey: toBase64Url(key.publicKey) }
    : { kid: toHex(key.kid), alg: 'Ed25519', publicKey: toBase64Url(key.publicKey), epk: epoch, validFrom };

/**
 * The manifest document as a deployment writes it. Members given last are appended after the seven this
 * version names, which is how the row about a member a reader does not know arrives in the position a
 * forward-compatible writer would put it.
 */
function documentOf(keys: readonly KeyEntry[], over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    iss: ISS,
    ins: INS,
    epk: 1,
    keys,
    models: MODELS,
    meas: MEASUREMENT,
    ...over,
  });
}

/** The honest document: one key, no declared windows, which is what a manifest looked like before them. */
const HONEST = documentOf([entryOf(RECEIPT_SIGNER)]);
const honestBytes = encodeText(HONEST);

/**
 * One position of a document text moved, which is how the two rows about *spelling* are built: the
 * members a reader parses to the same value are indistinguishable once parsed, so the only way to publish
 * the difference is the text it arrived in. A `from` appearing anywhere other than once refuses the run
 * rather than editing the wrong thing, because a fault case that moved two positions reports a fact about
 * nothing.
 */
function splice(text: string, from: string, to: string, where: string): string {
  const at = text.indexOf(from);
  if (at < 0 || text.indexOf(from, at + 1) >= 0) {
    throw new Error(`${where}: ${from} appears ${at < 0 ? 'nowhere' : 'more than once'} in the document text`);
  }
  return `${text.slice(0, at)}${to}${text.slice(at + from.length)}`;
}

/** The protected header this format writes, and the same one under another content type. */
function manifestHeader(kid: Uint8Array, contentType: string = DEPLOYMENT_MANIFEST_CONTENT_TYPE): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, ALG_EDDSA],
      [LABEL_TYP, contentType],
      [LABEL_KID, kid],
    ]),
  );
}

/**
 * A header spelled out of its parts, for the rows whose bytes no writer in this repository produces: an
 * undeclared label, a label or a value of another type, a `kid` of another width. Key and value bytes are
 * given alternately and in the order core deterministic encoding puts them, which the decoder's own
 * ordering check then enforces, so a header assembled here is not refused for the shape of its map.
 */
function handHeader(parts: readonly Uint8Array[]): Uint8Array {
  if (parts.length % 2 !== 0) throw new Error('a header given to this helper carries a label with no value');
  const bytes: number[] = [0xa0 + parts.length / 2];
  for (const one of parts) bytes.push(...one);
  return new Uint8Array(bytes);
}

/** The same header with an `alg` of the caller's choosing, which is the one label the writers here fix. */
function manifestHeaderWithAlg(alg: number): Uint8Array {
  return encodeCanonical(
    new Map<number, unknown>([
      [LABEL_ALG, alg],
      [LABEL_TYP, DEPLOYMENT_MANIFEST_CONTENT_TYPE],
      [LABEL_KID, SIGNER.kid],
    ]),
  );
}

/** Seal under a header of the caller's choosing, over the structure the shipping writer uses. */
function sealUnder(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
  key: SigningKey,
  externalAad: Uint8Array = EMPTY,
  unprotected: Map<unknown, unknown> = new Map(),
): Uint8Array {
  const signature = ed25519.sign(exportSigStructure(protectedBytes, payloadBytes, externalAad), key.privateKey);
  return sealExport(protectedBytes, payloadBytes, signature, unprotected);
}

/** The one envelope this suite's honest rows come out of, and the honest seal of a given document. */
const honestSeal = sealDeploymentManifest(honestBytes, SIGNER);
const sealOf = (text: string): Uint8Array => sealDeploymentManifest(encodeText(text), SIGNER);

/** The envelope of a whole document with one payload byte flipped and the old signature kept. */
function withPayloadFlipped(bytes: Uint8Array, at: number): Uint8Array {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  const [protectedBytes, unprotected, payload, signature] = contents as [Uint8Array, Map<unknown, unknown>, Uint8Array, Uint8Array];
  const edited = new Uint8Array(payload);
  edited[at] = (edited[at] ?? 0) ^ 0x01;
  return sealExport(protectedBytes, edited, signature, unprotected);
}

/** One policy entry: the id a client designated a manifest signer under, and the key it holds there. */
interface Pin {
  readonly kid: string;
  readonly publicKeyBase64Url: string;
}
const pinOf = (key: SigningKey): Pin => ({ kid: toHex(key.kid), publicKeyBase64Url: toBase64Url(key.publicKey) });

/** What a reader reports about the seal it was handed, which is one fact of the result and not a judgement. */
interface Authentication {
  readonly sealed: boolean;
  readonly authenticated: boolean;
  readonly kid: string | null;
  readonly demanded: boolean;
  readonly advisory: boolean;
}

/** One `keys[]` entry as the client's parser leaves it, with the two optional members only when declared. */
interface ParsedKey {
  readonly kid: string;
  readonly alg: 'Ed25519';
  readonly publicKey: string;
  readonly epk?: number;
  readonly validFrom?: number;
}

interface ParsedDocument {
  readonly v: 1;
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
  readonly keys: readonly ParsedKey[];
  readonly epochs: Array<{ epoch: number; validFrom: number; validTo: number | null; kids: readonly string[] }> | null;
  readonly models: readonly { id: string; wts: string }[];
  readonly meas: { tee: string; m: string };
}

/**
 * One epoch claim: what a receipt says about the key that signed it, and the answer this document's
 * rotation history gives. `adjudicateReceiptEpoch` is the shipped rule and the client path calls it, so
 * these rows are the manifest half of a receipt verdict rather than a second copy of one.
 */
interface EpochClaim {
  readonly claim: { kid: string; epoch: number; issuedAt: number };
  readonly ok: boolean;
  readonly code?: string;
  readonly basis?: 'windows' | 'current-epoch';
  readonly superseded?: boolean;
  readonly validFrom?: number | null;
  readonly validTo?: number | null;
}

/** The bytes handed to a reader, what it designates, and everything the two answers have to be. */
interface Case {
  readonly name: string;
  readonly note: string;
  readonly bytes: Uint8Array;
  /** The policy's designated manifest signing keys, which is the whole of the trust question. */
  readonly pins: readonly Pin[];
  /** What the client path answers, and `verify-ok` wherever it returns a document instead of throwing. */
  readonly verdict: string;
  /**
   * What the format package's envelope reader answers for the same bytes, verified under the key its own
   * protected header names. `not-sealed` for the rows a deployment serves as plain JSON.
   */
  readonly seal: string;
  readonly authentication?: Authentication;
  readonly parsed?: ParsedDocument;
  readonly dropped?: readonly string[];
  readonly edited?: string;
  readonly reveal?: Record<string, unknown>;
  readonly claims?: readonly EpochClaim[];
}

/** The reading of the honest document, which most accepting rows share and none of them re-derives. */
function reading(keys: readonly ParsedKey[], epochs: ParsedDocument['epochs'], over: Partial<ParsedDocument> = {}): ParsedDocument {
  return { v: 1, iss: ISS, ins: INS, epk: 1, keys, epochs, models: MODELS, meas: MEASUREMENT, ...over };
}

const authenticated: Authentication = { sealed: true, authenticated: true, kid: toHex(SIGNER.kid), demanded: true, advisory: false };

const CASES: readonly Case[] = [
  {
    name: 'sealed-under-designated-key',
    note: 'A whole manifest, sealed by the key a reader designates for the purpose, and the `Sig_structure` it was signed over, element by element. This is the state a client may act on: the document is the deployment\'s own statement, and `authenticated` is true because this client brought the key that says so.',
    bytes: honestSeal,
    pins: [pinOf(SIGNER)],
    verdict: 'verify-ok',
    seal: 'verify-ok',
    authentication: authenticated,
    parsed: reading([entryOf(RECEIPT_SIGNER)], null),
    claims: [
      {
        claim: { kid: toHex(RECEIPT_SIGNER.kid), epoch: 1, issuedAt: NOW },
        ok: true,
        basis: 'current-epoch',
        superseded: false,
        validFrom: null,
        validTo: null,
      },
      { claim: { kid: toHex(EXTRA_RECEIPT_KEY.kid), epoch: 1, issuedAt: NOW }, ok: false, code: 'MANIFEST_EPOCH_DISAGREES' },
      { claim: { kid: toHex(RECEIPT_SIGNER.kid), epoch: 2, issuedAt: NOW }, ok: false, code: 'MANIFEST_EPOCH_UNDECLARED' },
    ],
    reveal: {
      contextString: 'Signature1',
      externalAadBase64Url: toBase64Url(EMPTY),
      protectedHeaderBase64Url: toBase64Url(manifestHeader(SIGNER.kid)),
      payloadBase64Url: toBase64Url(honestBytes),
      payloadByteLength: honestBytes.length,
      payloadSha256Hex: toHex(digest(honestBytes)),
      signatureHex: toHex(decodeSealedDeploymentManifest(honestSeal).signature),
      sigStructureHex: toHex(exportSigStructure(manifestHeader(SIGNER.kid), honestBytes)),
      headerLabels: [
        { label: LABEL_ALG, name: 'alg', value: ALG_EDDSA },
        { label: LABEL_TYP, name: 'typ', value: DEPLOYMENT_MANIFEST_CONTENT_TYPE },
        { label: LABEL_KID, name: 'kid', value: toHex(SIGNER.kid) },
      ],
    },
  },
  {
    name: 'sealed-with-no-key-designated',
    note: 'The same bytes read by a client that designated no manifest signing key. This is not a failure and not a pass: nothing checked the seal, so the document is read, reported unauthenticated, and the advisory names the kid nothing vouched for. A suite that carried only the refusing states of this container would let a port collapse the advisory into either of the others.',
    bytes: honestSeal,
    pins: [],
    verdict: 'verify-ok',
    seal: 'verify-ok',
    authentication: { sealed: true, authenticated: false, kid: toHex(SIGNER.kid), demanded: false, advisory: true },
    parsed: reading([entryOf(RECEIPT_SIGNER)], null),
  },
  {
    name: 'unsigned-with-no-key-designated',
    note: 'The plain JSON document, which is what a deployment serves when it was handed no manifest signing key, read by a client that designated none either. The seal byte is what separates this from the row above and the reader decides off it rather than off a content type a sender chose.',
    bytes: honestBytes,
    pins: [],
    verdict: 'verify-ok',
    seal: 'not-sealed',
    authentication: { sealed: false, authenticated: false, kid: null, demanded: false, advisory: true },
    parsed: reading([entryOf(RECEIPT_SIGNER)], null),
  },
  {
    name: 'unsigned-while-a-key-is-designated',
    note: 'That same plain document served to a client that did name who may sign it. Nothing about the bytes is broken and nothing attributes them, which is the same refusal as a seal nobody designated and a different one from a signature that failed.',
    bytes: honestBytes,
    pins: [pinOf(SIGNER)],
    verdict: 'MANIFEST_NOT_AUTHENTICATED',
    seal: 'not-sealed',
  },
  {
    name: 'sealed-by-an-undesignated-key',
    note: 'A manifest sealed by another deployment\'s key, read by a client that designated one key. The envelope answers `verify-ok` here and that is the point: the seal is whole, this signature was made by the key its own header names, and the refusal is about who this client accepted responsibility for rather than about the bytes.',
    bytes: sealDeploymentManifest(honestBytes, SECOND_SIGNER),
    pins: [pinOf(SIGNER)],
    verdict: 'MANIFEST_NOT_AUTHENTICATED',
    seal: 'verify-ok',
  },
  {
    name: 'header-naming-one-key-signed-by-another',
    note: 'A protected header carrying the designated kid and a signature the designated key did not make, which is the one shape that separates a wrong key from an edited document. The kid check passes and the signature is what refuses, so the client reports tampering rather than a configuration it has to fix.',
    bytes: sealUnder(manifestHeader(SIGNER.kid), honestBytes, SECOND_SIGNER),
    pins: [pinOf(SIGNER)],
    verdict: 'MANIFEST_SIGNATURE_INVALID',
    seal: 'INVALID_SIGNATURE',
    edited: 'the private half that made the signature, with the header and payload left as signed',
  },
  {
    name: 'payload-byte-changed-after-sealing',
    note: 'One byte of a signed document flipped afterwards with the old signature left in place. The structure still reads, the kid still agrees, and the signature is what refuses it, which is the order a reader has to keep.',
    bytes: withPayloadFlipped(honestSeal, 40),
    pins: [pinOf(SIGNER)],
    verdict: 'MANIFEST_SIGNATURE_INVALID',
    seal: 'INVALID_SIGNATURE',
    edited: 'the forty-first byte of the payload, under the signature made for it',
  },
  {
    name: 'signed-over-a-non-empty-external-aad',
    note: 'The whole document and the whole header, signed over an external authenticated data string instead of the empty one this container uses. Nothing inside the envelope says which AAD was fed to the signer, so a reader that verified over a guess would report a good seal as a broken one and the other way round: this container has one answer and it is the empty string.',
    bytes: sealUnder(manifestHeader(SIGNER.kid), honestBytes, SIGNER, encodeText('ashaveri/deployment-manifest/v1')),
    pins: [pinOf(SIGNER)],
    verdict: 'MANIFEST_SIGNATURE_INVALID',
    seal: 'INVALID_SIGNATURE',
    edited: 'the external AAD fed to the signer, from empty to a label',
  },
  {
    name: 'pin-disagrees-with-its-own-digest',
    note: 'The policy designates a key id whose pinned public key hashes to something else. The document is not at fault and is not even reached: a pin and the id beside it cannot both be believed, and the refusal says which of the two the operator has to look at.',
    bytes: honestSeal,
    pins: [{ kid: toHex(SIGNER.kid), publicKeyBase64Url: toBase64Url(SECOND_SIGNER.publicKey) }],
    verdict: 'MANIFEST_KEY_NOT_PINNED',
    seal: 'verify-ok',
  },
  {
    name: 'protected-content-type-of-a-receipt',
    note: 'A receipt this repository actually publishes, the fixture payload signed by the committed fixture key, handed to the manifest reader. Both containers are `COSE_Sign1` over four elements and either verifies cleanly under the key it names, and the key this one is signed with is one the manifest beside it lists for signing receipts, so nothing about the signature or the key separates them. The content type is the only thing that tells a reader whether it is holding an attestation about one response or a deployment\'s statement about itself, and it is refused at the header before any key is consulted.',
    bytes: issueReceipt(fixturePayload(), RECEIPT_SIGNER),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
  },
  {
    name: 'protected-content-type-of-a-pack',
    note: 'A manifest document under the pack content type, signed by the key the header names so the seal is good. The refusal is the content type alone and nothing else about these bytes.',
    bytes: sealUnder(manifestHeader(SIGNER.kid, 'ashaveri/pack'), honestBytes, SIGNER),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
  },
  {
    name: 'protected-content-type-of-an-export',
    note: 'The same pair in the other direction, the export content type, which is the third container one deployment key signs. A reader of any of them that answered with the document it was hoping for would be reporting the wrong claim under a signature that held.',
    bytes: sealUnder(manifestHeader(SIGNER.kid, 'ashaveri/export'), honestBytes, SIGNER),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
  },
  {
    name: 'protected-header-carries-a-fourth-label',
    note: 'A protected header carrying a label this format does not declare, beside the three it does, and signed over as always. The header closes where the document inside it does not, and for a reason that only holds here: these bytes are hashed into the `Sig_structure`, so an extra label is an authenticated parameter and a reader that took the three it knows and returned those would hand on a different document from the one the deployment signed.',
    bytes: sealUnder(
      handHeader([
        encodeCanonical(LABEL_ALG),
        encodeCanonical(ALG_EDDSA),
        encodeCanonical(LABEL_TYP),
        encodeCanonical(DEPLOYMENT_MANIFEST_CONTENT_TYPE),
        encodeCanonical(LABEL_KID),
        encodeCanonical(SIGNER.kid),
        encodeCanonical(5),
        encodeCanonical('x'),
      ]),
      honestBytes,
      SIGNER,
    ),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
    edited: 'a fourth protected label, 5, carrying a tstr',
  },
  {
    name: 'protected-kid-of-another-width',
    note: 'A `kid` of thirty-one bytes, which is a declared label holding the wrong shape rather than an undeclared one. The width is what makes the field an id at all: it is sha256 of a public key, and a reader that took a shorter one would be resolving a key from bytes nothing hashes to.',
    bytes: sealUnder(
      handHeader([
        encodeCanonical(LABEL_ALG),
        encodeCanonical(ALG_EDDSA),
        encodeCanonical(LABEL_TYP),
        encodeCanonical(DEPLOYMENT_MANIFEST_CONTENT_TYPE),
        encodeCanonical(LABEL_KID),
        encodeCanonical(SIGNER.kid.slice(0, 31)),
      ]),
      honestBytes,
      SIGNER,
    ),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
    edited: 'the protected kid, one byte short of the digest it is meant to be',
  },
  {
    name: 'protected-alg-naming-another-suite',
    note: 'An `alg` of -7 where this container signs with EdDSA. The header refusal and this one are separate codes on purpose: one says the map is not the map this format declares and the other says the map is right and names a suite nothing here produces.',
    bytes: sealUnder(manifestHeaderWithAlg(-7), honestBytes, SIGNER),
    pins: [pinOf(SIGNER)],
    verdict: 'UNSUPPORTED_ALG',
    seal: 'UNSUPPORTED_ALG',
    edited: 'alg, from -8 to -7',
  },
  {
    name: 'protected-integer-spelled-as-a-float',
    note: 'The `alg` written as the half-precision float -8.0, which decodes to the very number the integer -8 decodes to, so a reader that checked values after the decode would accept these bytes and report a good EdDSA header. `manifest.cddl` declares integers at every position of this map, which is what makes a float a malformed document rather than a spelling, and the rule has to be part of the decode because nothing placed after one can recover which bytes wrote the value.',
    bytes: sealUnder(
      handHeader([
        encodeCanonical(LABEL_ALG),
        new Uint8Array([0xf9, 0xc4, 0x00]),
        encodeCanonical(LABEL_TYP),
        encodeCanonical(DEPLOYMENT_MANIFEST_CONTENT_TYPE),
        encodeCanonical(LABEL_KID),
        encodeCanonical(SIGNER.kid),
      ]),
      honestBytes,
      SIGNER,
    ),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
    edited: 'alg, written as the half-precision float -8.0 rather than the integer -8',
  },
  {
    name: 'protected-label-spelled-as-a-float',
    note: 'The same rule one position over: the label 1 written a second time as the float 1.0. A `Map` compares keys by value rather than by the bytes that wrote them, so the two spellings land in one slot and the map the reader is handed carries one entry where the signed bytes carry two. That is why this is refused at the decode and not reported as an `alg` problem, and why the value a naive reader would end up holding is whichever of the two encoding order put last.',
    bytes: sealUnder(
      handHeader([
        encodeCanonical(LABEL_ALG),
        encodeCanonical(ALG_EDDSA),
        new Uint8Array([0xf9, 0x3c, 0x00]),
        encodeCanonical(ALG_EDDSA),
        encodeCanonical(LABEL_TYP),
        encodeCanonical(DEPLOYMENT_MANIFEST_CONTENT_TYPE),
        encodeCanonical(LABEL_KID),
        encodeCanonical(SIGNER.kid),
      ]),
      honestBytes,
      SIGNER,
    ),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_PROTECTED_HEADER',
    seal: 'BAD_PROTECTED_HEADER',
    edited: 'a second label 1, written as the half-precision float 1.0',
  },
  {
    name: 'unprotected-map-carries-a-parameter',
    note: 'The whole document with the unprotected map filled instead of left empty. That map is the one place in this container a writer fills at will: it sits outside the signature, so nothing written in it travels as a claim about the deployment, and enforcing that it is empty would buy strictness with no security content behind it. The verdict is the honest one and does not move.',
    bytes: sealUnder(manifestHeader(SIGNER.kid), honestBytes, SIGNER, EMPTY, new Map<unknown, unknown>([['x', 'a parameter outside the signature']])),
    pins: [pinOf(SIGNER)],
    verdict: 'verify-ok',
    seal: 'verify-ok',
    authentication: authenticated,
    parsed: reading([entryOf(RECEIPT_SIGNER)], null),
  },
  {
    name: 'envelope-without-its-tag',
    note: 'The four elements of a `COSE_Sign1` with the tag around them missing, which is the consequence of deciding which of the two shapes arrived off one byte. Those bytes no longer begin with the tag, so the reader takes them for the plain document, cannot parse them as JSON, and answers about the manifest rather than about the envelope: `NOT_COSE_SIGN1` is unreachable from a client that never looked at the structure, and a port that reported it here has built its reading of the branch off something other than the first byte.',
    bytes: encodeCanonical((decodeCanonical(honestSeal) as { contents: unknown }).contents),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'not-sealed',
  },
  {
    name: 'envelope-whose-signature-is-not-64-bytes',
    note: 'The same envelope with one byte taken off the end of the signature, which is a shape refusal rather than a cryptography failure. A reader that reached the verification step with a truncated signature would be reporting a wrong answer about the wrong bytes.',
    bytes: sealExport(manifestHeader(SIGNER.kid), honestBytes, ed25519.sign(exportSigStructure(manifestHeader(SIGNER.kid), honestBytes), SIGNER.privateKey).slice(0, 63)),
    pins: [pinOf(SIGNER)],
    verdict: 'NOT_COSE_SIGN1',
    seal: 'NOT_COSE_SIGN1',
    edited: 'the last byte of the signature',
  },
  {
    name: 'envelope-truncated-mid-document',
    note: 'The first twenty-four bytes of a whole sealed manifest, so nothing decodes and no header, key or document is ever reached.',
    bytes: honestSeal.slice(0, 24),
    pins: [pinOf(SIGNER)],
    verdict: 'MALFORMED_CBOR',
    seal: 'MALFORMED_CBOR',
  },
  {
    name: 'rotation-history-retaining-a-superseded-key',
    note: 'The same document with the two optional members of `keys[]` filled in: two keys, two epochs, the lower one superseded and still retained. No upper bound is written down anywhere, because two members that must agree are two chances to publish a gap and an overlap, so the end of a window is the start of the epoch above it and the highest epoch has no published end. The claims below are what that history answers, half-open at the successor\'s start.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER, 1, EPOCH_ONE_START), entryOf(EXTRA_RECEIPT_KEY, 2, NOW)], { epk: 2 })),
    pins: [pinOf(SIGNER)],
    verdict: 'verify-ok',
    seal: 'verify-ok',
    authentication: authenticated,
    parsed: reading(
      [entryOf(RECEIPT_SIGNER, 1, EPOCH_ONE_START), entryOf(EXTRA_RECEIPT_KEY, 2, NOW)],
      [
        { epoch: 1, validFrom: EPOCH_ONE_START, validTo: NOW, kids: [toHex(RECEIPT_SIGNER.kid)] },
        { epoch: 2, validFrom: NOW, validTo: null, kids: [toHex(EXTRA_RECEIPT_KEY.kid)] },
      ],
      { epk: 2 },
    ),
    claims: [
      {
        claim: { kid: toHex(RECEIPT_SIGNER.kid), epoch: 1, issuedAt: NOW - 1 },
        ok: true,
        basis: 'windows',
        superseded: true,
        validFrom: EPOCH_ONE_START,
        validTo: NOW,
      },
      { claim: { kid: toHex(RECEIPT_SIGNER.kid), epoch: 1, issuedAt: NOW }, ok: false, code: 'MANIFEST_EPOCH_DISAGREES' },
      { claim: { kid: toHex(EXTRA_RECEIPT_KEY.kid), epoch: 1, issuedAt: NOW - 1 }, ok: false, code: 'MANIFEST_EPOCH_DISAGREES' },
      { claim: { kid: toHex(RECEIPT_SIGNER.kid), epoch: 3, issuedAt: NOW }, ok: false, code: 'MANIFEST_EPOCH_UNDECLARED' },
    ],
  },
  {
    name: 'document-member-unknown-to-version-one',
    note: 'A manifest carrying two members version 1 names nowhere, one at the top level and one inside a key entry. The parser is open here and that is a decision rather than a gap: a manifest is a deployment\'s own current statement about itself, and the only way it can grow without every client updating in step is for a reader to be permitted to leave what it does not know alone. Both members are read as nothing and dropped, and the document is accepted under the seal. The same row read against a reader that refuses unknown members fails here, which is the half a closed format cannot test.',
    bytes: sealOf(
      splice(
        documentOf([entryOf(RECEIPT_SIGNER)], { future: 'a member no version names', touchedAt: NOW }),
        `"publicKey":"${toBase64Url(RECEIPT_SIGNER.publicKey)}"}`,
        `"publicKey":"${toBase64Url(RECEIPT_SIGNER.publicKey)}","note":"beside a key entry"}`,
        'a member inside a key entry',
      ),
    ),
    pins: [pinOf(SIGNER)],
    verdict: 'verify-ok',
    seal: 'verify-ok',
    authentication: authenticated,
    parsed: reading([entryOf(RECEIPT_SIGNER)], null),
    dropped: ['future', 'touchedAt', 'note'],
  },
  {
    name: 'manifest-version-two',
    note: 'A document declaring a manifest version nothing has published. Openness is about members a version does not name and not about a version a reader has no reading for: `v` is the one member that has to match, because a document from a later version can rename what the open reader is leaving alone.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER)], { v: 2 })),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'v, from 1 to 2',
  },
  {
    name: 'epoch-declared-without-a-window-start',
    note: 'A key entry naming the epoch it signed under and no instant at which that epoch became acceptable. One member of the pair states nothing a reader can use: the window is open-ended in one direction and unbounded in the other, so this is a manifest that began declaring a rotation history and stopped halfway, and the reading that would accept it is the one that never retires a key.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER, 1)])),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'the keys[0] entry, `validFrom` left out of the declared pair',
  },
  {
    name: 'rotation-history-half-declared',
    note: 'Two key entries where one names an epoch and a start and the other names neither. The array has one shape or the other, and a reader that let the mixed case through would be reporting the second key as belonging to no epoch at all, which is the state a manifest published before this rule had and is not the state of this document.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER, 1, EPOCH_ONE_START), entryOf(EXTRA_RECEIPT_KEY)])),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'a second keys[] entry naming neither epoch nor start',
  },
  {
    name: 'one-epoch-two-window-starts',
    note: 'The same epoch declared by two entries with two different starts. A reader holding two bounds for one epoch has to pick one and nothing in the document says which, so the disagreement is refused rather than resolved by the order the array happens to be in.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER, 1, EPOCH_ONE_START), entryOf(EXTRA_RECEIPT_KEY, 1, NOW)])),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'epoch 1 declared twice, at 1700000000 and at the document\'s own instant',
  },
  {
    name: 'window-starts-not-ascending-with-epochs',
    note: 'Epoch 4 published as starting before epoch 3. Without this rule the bound of a retained key comes out of the entry beside it and two windows contain the present moment, so which key a receipt verifies under depends on which of the two a reader reaches first. Refusing the pair is what keeps a window end a fact of the document rather than an artefact of a loop.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER, 4, EPOCH_ONE_START), entryOf(EXTRA_RECEIPT_KEY, 3, NOW)], { epk: 4 })),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'the epoch numbers, so the higher one starts earlier',
  },
  {
    name: 'epoch-count-fractional',
    note: 'A top-level `epk` of 1.5. An epoch is a count of rotations and the manifest\'s own number rule is that a fractional value stands for nothing, so this is refused where the window start beside it is not.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER)], { epk: 1.5 })),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'epk, from 1 to 1.5',
  },
  {
    name: 'window-start-spelled-with-a-decimal-point',
    note: 'The same number written in JSON as `1700000000.0`, which is the case this container answers the opposite way to its CBOR header. A payload is JSON and a JSON number that is a whole one is that whole number by the time any reader looks at it, so this is the integer the format declares and the document is accepted. The rule about floats lives where the bytes carry a type, which is the envelope, and a port that went looking for it in the payload will refuse a deployment that is writing valid manifests.',
    bytes: sealOf(
      splice(documentOf([entryOf(RECEIPT_SIGNER, 1, EPOCH_ONE_START)]), `"validFrom":${EPOCH_ONE_START}`, `"validFrom":${EPOCH_ONE_START}.0`, 'the window start'),
    ),
    pins: [pinOf(SIGNER)],
    verdict: 'verify-ok',
    seal: 'verify-ok',
    authentication: authenticated,
    parsed: reading([entryOf(RECEIPT_SIGNER, 1, EPOCH_ONE_START)], [
      { epoch: 1, validFrom: EPOCH_ONE_START, validTo: null, kids: [toHex(RECEIPT_SIGNER.kid)] },
    ]),
  },
  {
    name: 'key-id-in-uppercase-hex',
    note: 'A `keys[]` kid spelled with capital letters, which is the same sixty-four nibbles and not the same document. Every byte string this format fixes a width for is lowercase hex on the wire, and an id is looked up by comparison rather than by a case-folding parse, so a reader that accepted this spelling would resolve one key from two different texts.',
    bytes: sealOf(documentOf([{ ...entryOf(RECEIPT_SIGNER), kid: toHex(RECEIPT_SIGNER.kid).toUpperCase() }])),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'the case of the key id',
  },
  {
    name: 'public-key-in-padded-base64url',
    note: 'A key\'s `publicKey` carrying its `=` padding. The alphabet is right and the width is not: unpadded base64url of thirty-two bytes is forty-three characters and a reader that tolerated padding would accept a value the manifest never writes.',
    bytes: sealOf(documentOf([{ ...entryOf(RECEIPT_SIGNER), publicKey: Buffer.from(RECEIPT_SIGNER.publicKey).toString('base64') }])),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'the key\'s public half, in padded standard base64',
  },
  {
    name: 'measurement-in-uppercase-hex',
    note: 'The launch measurement capitalized, which is the same digest and a different text. A pin a client holds is compared as written, so a deployment that published its measurement in capitals would fail a check its own document says it meets.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER)], { meas: { tee: 'software', m: MEASUREMENT.m.toUpperCase() } })),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'the case of the measurement hex',
  },
  {
    name: 'measurement-width-not-its-environment-kind',
    note: 'A measurement of the width a software deployment reports under an environment kind that reports a longer one. Width and kind are one fact rather than two that can disagree, and a reader that checked the length alone would accept a platform claim with the wrong evidence behind it.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER)], { meas: { tee: 'snp', m: MEASUREMENT.m } })),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'meas.tee, to a kind whose measurement is forty-eight bytes',
  },
  {
    name: 'measurement-kind-nothing-names',
    note: 'An environment kind this repository declares no width for. The kind decides how long the digest beside it has to be, so an unknown one cannot be read at all rather than read and left alone the way an unknown member is.',
    bytes: sealOf(documentOf([entryOf(RECEIPT_SIGNER)], { meas: { tee: 'sme', m: MEASUREMENT.m } })),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'meas.tee, to a kind the registry does not hold',
  },
  {
    name: 'no-keys-listed',
    note: 'An empty `keys` array. A manifest with no keys states nothing a verifier can check a receipt against and is a deployment that has stopped being verifiable rather than one that is between rotations.',
    bytes: sealOf(documentOf([])),
    pins: [pinOf(SIGNER)],
    verdict: 'BAD_MANIFEST',
    seal: 'verify-ok',
    edited: 'the keys array, emptied',
  },
];

/**
 * What the format package's own envelope reader answers for these bytes, verified under the key its
 * protected header names. This is the witness that keeps the `seal` field of every published row a fact
 * about bytes rather than an expectation about them.
 */
function sealVerdictOf(bytes: Uint8Array): string {
  if (!isSealedDeploymentManifest(bytes)) return 'not-sealed';
  try {
    const seal = decodeSealedDeploymentManifest(bytes);
    const signer = KEY_BY_KID.get(toHex(seal.header.kid));
    if (signer === undefined) return 'kid-not-published-by-this-suite';
    verifySealedDeploymentManifest(bytes, signer.publicKey);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`the envelope reader raised something with no code: ${String(err)}`);
  }
}

function published(one: Case): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    documentBase64Url: toBase64Url(one.bytes),
    documentByteLength: one.bytes.length,
    read: { designates: one.pins },
    verdict: one.verdict,
    seal: one.seal,
    ...(one.authentication === undefined ? {} : { authentication: one.authentication }),
    ...(one.parsed === undefined ? {} : { parsed: one.parsed }),
    ...(one.dropped === undefined ? {} : { dropped: one.dropped }),
    ...(one.claims === undefined ? {} : { claims: one.claims }),
    ...(one.edited === undefined ? {} : { edited: one.edited }),
    ...(one.reveal === undefined ? {} : { reveal: one.reveal }),
  };
}

function main() {
  // The hand-assembled rows are only honest if the path that builds them writes what the shipping writer
  // writes, so that is checked before a single case is: same header, same payload, same key, same bytes.
  const canonicalHeader = manifestHeader(SIGNER.kid);
  const handBuilt = sealUnder(canonicalHeader, honestBytes, SIGNER);
  if (toHex(handBuilt) !== toHex(honestSeal)) {
    throw new Error('the hand-assembled envelope is not the one sealDeploymentManifest writes');
  }

  // And the writer is asked to produce the class this suite refuses at the key level, which it will not:
  // a signing key whose kid is not sha256 of its own public half is refused at the point the bytes are
  // made, so no deployment can seal a document under an id that does not resolve.
  let writerRefused = false;
  try {
    sealDeploymentManifest(honestBytes, { ...SIGNER, kid: new Uint8Array(32) });
  } catch (err) {
    writerRefused = err instanceof ReceiptError && err.code === 'BAD_SIGNING_KEY';
  }
  if (!writerRefused) throw new Error('the manifest writer accepted a signing key whose kid is not its digest');

  for (const one of CASES) {
    const observed = sealVerdictOf(one.bytes);
    if (observed !== one.seal) {
      throw new Error(`${one.name}: the envelope reader answers ${observed}, not the ${one.seal} this file states`);
    }
  }

  const names = CASES.map((one) => one.name);
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  const sealed = CASES.filter((one) => one.seal === 'verify-ok');
  if (sealed.length === 0) throw new Error('this suite publishes no document whose seal holds');
  const refused = CASES.filter((one) => one.verdict !== 'verify-ok');
  if (refused.length === 0) throw new Error('this suite publishes no refusal');

  writeFileSync(
    join(DATA, 'manifest-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'Deployment manifests in both shapes a deployment serves, the manifest signing keys a reader designates beside each one, and the verdict the client path owes it: three states of a whole document, and one refusal for every fault the envelope and the document name.',
        layout: {
          format: 'packages/receipt/manifest.cddl',
          twin: 'packages/receipt/schemas/manifest-v1.schema.json',
          prose: 'docs/receipt-spec.md section 4.4',
          contentType: DEPLOYMENT_MANIFEST_CONTENT_TYPE,
          reader:
            'readDeploymentManifest in @ashaveri/sdk, which calls decodeSealedDeploymentManifest and verifySealedDeploymentManifest from @ashaveri/receipt and parseManifest from @ashaveri/sdk',
          envelopeReader:
            'decodeSealedDeploymentManifest and verifySealedDeploymentManifest in @ashaveri/receipt, which is the half this generator ran over these bytes when it wrote them',
          headerLabels: { alg: LABEL_ALG, typ: LABEL_TYP, kid: LABEL_KID },
          headerCloses:
            'the protected header carries exactly the three labels above and no fourth, because its bytes are hashed into the signature; the document inside the payload is read openly, and a member version 1 does not name is left alone',
          sigStructure:
            'RFC 9052 section 4.4: the array ["Signature1", the protected bstr as written, the external AAD, the payload bstr], canonically encoded. The external AAD is empty for this container and nothing inside the envelope carries which one was used.',
          payload:
            'the deployment manifest JSON document as UTF-8, signed byte for byte: no re-encode, no key order chosen on the way, so what a client verifies is what it read. The one case that separates a document from its rendering is a key id written in capitals.',
          integers:
            'no floating-point number stands where the CBOR declares an integer, in a label or in a value, and the rule lives in the envelope rather than the payload: a JSON number that is a whole one is that whole number by the time a document is read.',
          decidesSealedOrPlain:
            'the first byte, 0xd2 for a `COSE_Sign1` and no JSON text beginning with it, rather than a content type a sender chose. `isSealedDeploymentManifest` is the shipped reading. It has a consequence past the branch: bytes that meant to be an envelope and lost their tag are read as the plain document and refused as a manifest, so `NOT_COSE_SIGN1` is reached only behind a first byte that claims the tag.',
          encodings: 'documents and byte strings unpadded base64url, digests, kids and signatures lowercase hex, instants unix seconds',
          verdictFields: ['verdict', 'seal', 'authentication', 'parsed', 'dropped', 'claims', 'edited', 'reveal'],
          verdictMeaning:
            '`verdict` is what the client path answers: `verify-ok`, or the code it throws. `seal` is what the envelope reader answers for the same bytes run under the key the protected header names: `verify-ok`, `not-sealed`, or the code. A row whose `seal` is `verify-ok` and whose `verdict` is a refusal is refusing about designation, not about tampering.',
          authenticationFields: ['sealed', 'authenticated', 'kid', 'demanded', 'advisory'],
          claimsField:
            '`claims` are receipts\' epoch claims, each stated as the kid, the epoch and the stamp a receipt carries, adjudicated by `adjudicateReceiptEpoch` against the manifest this row\'s document parses to. Each is spelled as the shipped rule takes it, `epoch` and `issuedAt` for the `epk` and `iat` a receipt carries. They are the document half of a receipt verdict and they decide nothing about a key.',
          codes: [...new Set(CASES.map((one) => one.verdict))].sort(),
          assembled:
            'every honest seal is `sealDeploymentManifest` and no hand-built bytes. Where a row needs a protected header that writer will not write, an undeclared label, a label or value of another type, a kid of another width, an `alg` other than EdDSA, a content type other than this one, a non-empty unprotected map, a truncated signature or a non-empty external AAD, the header is encoded from its parts, signed over the published `Sig_structure`, and assembled by the published tag-18 writer; the generator stops unless that path reproduces `sealDeploymentManifest` byte for byte on the canonical header, so each fault below is the one position its `edited` field names and nothing else. The writer is also asked to seal under a key whose kid is not sha256 of its public half and refuses with `BAD_SIGNING_KEY`, which is why this suite carries no such row.',
          documentFaults:
            'the rows whose `seal` is `verify-ok` and whose `verdict` is `BAD_MANIFEST` are documents the writer sealed exactly as given: the signature holds and the document inside it does not parse. That is the state of a deployment that published a manifest no client can read, and it is a different answer from tampering.',
          keyMaterial: KEY_MATERIAL.map((one) => ({
            id: toHex(one.key.kid).slice(0, 8),
            seed: one.seed,
            kidHex: toHex(one.key.kid),
            publicKeyHex: toHex(one.key.publicKey),
            publicKeyBase64Url: toBase64Url(one.key.publicKey),
            role: one.role,
          })),
          keyNote:
            'test-only, published so a port can produce these signatures itself rather than only checking them, and protecting nothing. The manifest signing keys are derived apart from the receipt signing key on purpose: a deployment signs receipts with one key and manifests with another, and a wrapper that verified under a receipt signing key would let one compromised signing key rewrite the rotation record meant to retire it.',
        },
        vectors: CASES.map(published),
        crossReading: {
          note: 'One deployment, four containers, all of them `COSE_Sign1` over four elements and each verifying cleanly under a key a reader trusted. Each reader refuses the others\' document at its protected header, before a key is consulted, and the manifest side of that pair is in the rows named `protected-content-type-*`. This is the other side: the honest manifest above handed to the receipt reader, which is the confusion the content type exists to prevent.',
          cases: [
            {
              name: 'manifest-read-as-receipt',
              note: 'The honest sealed manifest, decoded by the receipt container\'s reader. The header decodes, the label set is right, and the `typ` is not the receipt\'s, so the answer is the header refusal rather than a payload problem the bytes do not have.',
              documentBase64Url: toBase64Url(honestSeal),
              expected: decodeRefusalOfReceiptReader(honestSeal),
            },
          ],
        },
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of CASES) console.log(`${one.name}: ${one.seal} -> ${one.verdict}`);
}

/** The receipt reader's own answer to a sealed manifest, witnessed rather than asserted. */
function decodeRefusalOfReceiptReader(bytes: Uint8Array): string {
  try {
    decodeCoseSign1(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw new Error(`the receipt reader raised something with no code: ${String(err)}`);
  }
}

main();
