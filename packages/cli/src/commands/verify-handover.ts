import { stat } from 'node:fs/promises';
import { basename } from 'node:path';
import {
  COSE_SIGN1_TAG,
  DEPLOYMENT_MANIFEST_CONTENT_TYPE,
  EXPORT_CONTENT_TYPE,
  PACK_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  decodeCanonical,
  ReceiptError,
  verifyExport,
  verifyPack,
  verifyReceipt,
  type VerifiedExport,
  type VerifiedPack,
  type VerifiedReceipt,
} from '@ashaveri/receipt';
import {
  fromBase64Url,
  readDeploymentManifest,
  SdkError,
  toHex,
  type AshaveriPolicy,
} from '@ashaveri/sdk';
import { escapeInvisible, UsageError, writeJson } from '../usage.js';
import {
  KEY_FLAG,
  MANIFEST_KEY_FLAG,
  designatedKeys,
  readBytes,
  type DesignatedKey,
} from './verify-receipt.js';

/**
 * `ashaveri verify-handover <document> [options]`: what is this file, and what holds for it.
 *
 * A verification bundle is a pile of files, and four of the shapes it can hold now carry a published
 * content type: `ashaveri/receipt`, `ashaveri/pack`, `ashaveri/export` and `ashaveri/deployment-manifest`.
 * Two of them had a reader and no verb anybody could run, so a person handed the pile could not ask
 * what any of it was. This is that question, answered by one command rather than by four, because the
 * answer is inside the document: the content type sits in the COSE protected header, the header is
 * inside the signature, and so a stranger holding no key and reaching no network can classify these
 * bytes safely. A command per format would have made the caller declare the shape before reading it,
 * which is the one thing a pile makes impossible.
 *
 * The type is printed first in every answer this command gives, before anything about validity,
 * because a verdict about the wrong document is not a verdict at all.
 *
 * The dispatch is a lookup against the four constants the format package publishes, and each of the
 * four readers re-answers the content type itself, over the protected bytes, inside its own signature
 * check. That is why a relabelled document cannot be talked into a pass here: the classification picks
 * which reader runs, and only a reader that has verified a signature over the header it read reports a
 * document as verified. A header changed without re-signing is caught by the signature, and a header
 * that is honest about a shape this command does not read is refused by name.
 *
 * Which keys a document is checked against stays the caller's designation, exactly as
 * `ashaveri verify-receipt` treats one. `--key` designates the keys whose signatures this run accepts
 * on receipts, packs and exports, matched by the kid a header names; `--manifest-key` designates the
 * keys whose seal authenticates a deployment manifest. The two roles are kept apart for the reason the
 * policy type gives them: a manifest decides which keys sign evidence, so a key trusted for evidence
 * cannot also be the proof that the document naming them is the deployment's own. Each designation's
 * kid is computed from the key rather than typed beside it, so a designation that contradicts its own
 * key is refused before a byte of anybody's material is read, and what it refused is the call rather
 * than the document. Which keys a run was handed, and whether the document in front of it consulted
 * them, are printed either way, because a designation that did nothing is worth as much disclosing as
 * one that did.
 *
 * What this command does not decide is stated in its own output rather than left implied. It applies no
 * policy, compares a nonce against no challenge and reads no age window, because those are answers about
 * one request and one clock, and they belong to `verify-receipt`, which enforces them through the same
 * code a client enforces them in while a deployment is answering. Copying them here would leave two
 * copies of the rules that decide what a receipt means, and only one of them is the one an auditor is
 * told about. So a receipt read here comes back signed by a key this run designated and whole in its own
 * shape, and the report says in terms which questions that leaves open and which command closes them.
 *
 * Two of the four shapes have a verb of their own beside this one: `ashaveri verify-pack` and
 * `ashaveri verify-export`. They are this command with the answer in label 3 pinned to one value, so a
 * caller that already knows which file it is holding is told, in the same refusal this command gives a
 * type it does not read, when the file in front of it is not that. They add no exit code, no refusal code
 * and no option, because there is nothing here that a pinned type needs and a free type does not.
 */

/** The flags `verify-handover` reads, typed as the one parse in `cli.ts` produces them. */
export interface VerifyHandoverFlags {
  /** Every `--key` given, unvalidated at this point; see `designatedKeys`. */
  key?: string[];
  /** Every `--manifest-key` given, unvalidated at this point; see `designatedKeys`. */
  'manifest-key'?: string[];
  /** Every `--companion` given: the files an export item's originals travel in. */
  companion?: string[];
  json?: boolean;
}

/**
 * What a verb of this family answers to, and which document it will read.
 *
 * `contentType: null` is the question rather than an absence of one: it says this verb asks the bytes
 * which shape they are, which is what a pile of files leaves open. A verb that names one type reads only
 * that type and refuses another, and the refusal it owes for that is this command's own refusal for a
 * content type it does not hold a reader for, because the fact a caller needs is the same fact in both
 * cases and a second code for it would be a second thing to learn about one document.
 */
export interface VerbPin {
  /** The verb as typed, which is the name an argument refusal quotes back. */
  readonly verb: string;
  /** The protected content type this verb reads, or null to read whichever one the bytes claim. */
  readonly contentType: string | null;
}

/** `ashaveri verify-handover`, the verb that answers the question a pile of files leaves open. */
export const HANDOVER_VERB: VerbPin = { verb: 'verify-handover', contentType: null };

/** Label 3 of the COSE header registry: the content type. The four formats all put their name there. */
const CONTENT_TYPE_LABEL = 3;

/** Label 4 of the same registry: the kid. Every one of the four readers requires it to be 32 bytes. */
const KID_LABEL = 4;

/** The width a kid is written at across these formats, which is what the readers refuse anything else for. */
const KID_BYTES = 32;

/** One reported item, in the two shapes a reader meets it in: a printed row and a JSON member. */
interface Fact {
  /** The JSON member name. */
  readonly key: string;
  /** The printed label, in the words an operator reads. */
  readonly label: string;
  readonly value: string;
  readonly json: unknown;
}

/** One document, classified and read. Both renderings are built from this and from nothing else. */
interface Reading {
  readonly contentType: string;
  /** The reader that accepted the bytes, named so a report says which rules ran instead of implying it. */
  readonly reader: string;
  /** The kid the protected header designates, hex, which is what a designated key is matched on. */
  readonly kid: string;
  readonly facts: readonly Fact[];
  /** What this run left open, in the words the report prints under them. */
  readonly notChecked: readonly string[];
}

/** Everything the four readers share: what this run was handed, and the bytes it was handed. */
interface Inputs {
  readonly evidence: readonly DesignatedKey[];
  readonly manifest: readonly DesignatedKey[];
  readonly companions: ReadonlyMap<string, Uint8Array>;
}

/** The refusal every command in this tool owes in the same shape: the code, and the message beside it. */
function refuse(contentType: string | null, err: ReceiptError | SdkError, json: boolean): number {
  if (json) {
    writeJson({
      ok: false,
      ...(contentType === null ? {} : { contentType }),
      code: err.code,
      message: err.message,
    });
  } else {
    const found = contentType === null ? '' : `${contentType}: `;
    process.stderr.write(`${found}verification failed (${err.code}): ${escapeInvisible(err.message)}\n`);
  }
  return 1;
}

/**
 * What these bytes call themselves, read out of the envelope by the package's own CBOR decoder.
 *
 * Nothing is decided about trust here, and nothing needs to be: this answers only which reader the
 * bytes point at, and which kid that reader will be asked to settle. The codes are the ones the four
 * readers already use for the same four facts about an envelope, because a caller who meets a refusal
 * here and then in a reader should learn one thing twice rather than two things once, and because a
 * command that classified documents is not the place a new refusal code is born.
 *
 * `expected` is the verb's own pin, and it is answered in the same breath as a type no reader is held
 * for, with the same refusal: a verb that reads packs and is handed an export has met a document it was
 * not asked about, which is the one fact a content type states.
 */
function classify(bytes: Uint8Array, expected: string | null): { contentType: string; kid: Uint8Array } {
  let top: unknown;
  try {
    top = decodeCanonical(bytes);
  } catch (err) {
    throw new ReceiptError(
      'MALFORMED_CBOR',
      `a deployment manifest served as unsigned JSON is such a file, and 'ashaveri verify-receipt --manifest <file>' is the command that reads it: these bytes carry no COSE protected header to classify, because ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (typeof top !== 'object' || top === null || !('tag' in top) || !('contents' in top)) {
    throw notSign1();
  }
  if (top.tag !== COSE_SIGN1_TAG) {
    throw notSign1();
  }
  const elements: readonly unknown[] = Array.isArray(top.contents) ? (top.contents as readonly unknown[]) : [];
  if (elements.length !== 4) {
    throw notSign1();
  }
  const protectedBytes = elements[0];
  if (!(protectedBytes instanceof Uint8Array)) {
    throw new ReceiptError('NOT_COSE_SIGN1', 'protected is not a bstr');
  }
  let header: unknown;
  try {
    header = decodeCanonical(protectedBytes);
  } catch (err) {
    throw new ReceiptError(
      'BAD_PROTECTED_HEADER',
      `the protected header is not canonical CBOR, and it is the one part of the envelope a reader has to open before it can decide anything: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!(header instanceof Map)) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', 'not a map');
  }
  // The labels are read as `unknown` on purpose: `instanceof Map` hands back a map of `any`, and the
  // values below are bytes and text from a document nobody has signed yet, so an implicit `any` here
  // would let a value through to a template without a check being noticed as missing.
  const entries: Map<unknown, unknown> = header;
  const kid = entries.get(KID_LABEL);
  if (!(kid instanceof Uint8Array) || kid.length !== KID_BYTES) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', 'kid must be a 32-byte bstr');
  }
  const contentType = entries.get(CONTENT_TYPE_LABEL);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  if (!READERS.has(contentType) || (expected !== null && expected !== contentType)) {
    // The readers' own wording for the same fact: what a content type is for is answered by the set of
    // types that exist, and an unknown one is named back rather than guessed at. A verb pinned to one of
    // the types that do exist meets this same refusal here, because the fact it needs to state, that this
    // document is not the shape that verb reads, is the fact label 3 carries and no other field can.
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ=${contentType}`);
  }
  return { contentType, kid };
}

/** The one refusal for bytes that decode but are not a `COSE_Sign1`. */
function notSign1(): ReceiptError {
  return new ReceiptError(
    'NOT_COSE_SIGN1',
    'top-level value is not a COSE_Sign1 (tag 18) structure of four elements. Every document this command classifies is signed, so an unsigned file has no protected header and no content type to read',
  );
}

/**
 * The key set this run designates for evidence, answered the way the receipt and pack readers ask.
 *
 * A resolver rather than one pinned key, because a pack's span can cross a key rotation and the
 * receipts inside it were signed by the epochs that were current then, which is what the caller
 * retained. Which kid names which key is the caller's fact; nothing here authenticates a key.
 */
function resolveEvidence(keys: readonly DesignatedKey[]): (kid: Uint8Array) => Uint8Array | undefined {
  const byKid = new Map(keys.map((one) => [one.kid, one.publicKey]));
  return (kid) => {
    const designated = byKid.get(toHex(kid));
    return designated === undefined ? undefined : fromBase64Url(designated);
  };
}

function isoOf(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

/**
 * A receipt, read as a receipt.
 *
 * `verifyReceipt` is the shipped reader, so the signature rule, the kid rule and the payload rules are
 * the ones a client applies. What this command deliberately does not pass it is the caller's side of a
 * transaction: no challenge, no request or response bytes, no policy pins, no clock. Those are printed
 * as open questions naming the verb that closes them, because a report that said "verified" about a
 * receipt whose nonce nobody compared would be claiming the one thing a receipt is for.
 */
function readReceipt(bytes: Uint8Array, inputs: Inputs, kid: Uint8Array): Reading {
  const verified: VerifiedReceipt = verifyReceipt(bytes, { resolveKey: resolveEvidence(inputs.evidence) });
  const payload = verified.payload;
  return {
    contentType: RECEIPT_CONTENT_TYPE,
    reader: 'verifyReceipt',
    kid: toHex(kid),
    facts: [
      { key: 'signature', label: 'signature', value: 'holds, EdDSA over the Sig_structure a receipt frames, under the designated key', json: true },
      { key: 'payloadVersion', label: 'payload', value: `v${payload.v}`, json: payload.v },
      { key: 'issuer', label: 'issuer', value: payload.iss, json: payload.iss },
      { key: 'instance', label: 'instance', value: payload.ins, json: payload.ins },
      { key: 'model', label: 'model', value: payload.mdl, json: payload.mdl },
      { key: 'weights', label: 'weights', value: toHex(payload.wts), json: toHex(payload.wts) },
      { key: 'issuedAt', label: 'issued at', value: `${payload.iat} (${isoOf(payload.iat)})`, json: payload.iat },
      { key: 'keyEpoch', label: 'key epoch', value: String(payload.epk), json: payload.epk },
      { key: 'measurement', label: 'measurement', value: `${toHex(payload.meas.m)} (${payload.meas.tee})`, json: { tee: payload.meas.tee, m: toHex(payload.meas.m) } },
      { key: 'requestDigest', label: 'request digest', value: toHex(payload.req), json: toHex(payload.req) },
      { key: 'responseDigest', label: 'response digest', value: toHex(payload.res), json: toHex(payload.res) },
      { key: 'nonce', label: 'nonce', value: toHex(payload.nce), json: toHex(payload.nce) },
      {
        key: 'markedRegion',
        label: 'marked region',
        value: payload.v === 2 ? `${toHex(payload.mk.d)} (${payload.mk.sch})` : 'a v1 payload states none',
        json: payload.v === 2 ? { scheme: payload.mk.sch, sha256: toHex(payload.mk.d) } : null,
      },
      { key: 'tokens', label: 'tokens', value: `${payload.tok.p} prompt, ${payload.tok.c} completion`, json: { prompt: payload.tok.p, completion: payload.tok.c } },
      {
        key: 'evidence',
        label: 'evidence ref',
        value: `${toHex(payload.att.d)} at ${payload.att.ts} (${isoOf(payload.att.ts)})`,
        json: { digest: toHex(payload.att.d), timestamp: payload.att.ts },
      },
    ],
    notChecked: [
      `the nonce against a challenge, the two digests against any bytes, the pins a policy names and the age windows a clock closes: 'ashaveri verify-receipt' decides those, from the receipt, a policy file and a deployment manifest`,
      'the evidence document behind att.d, which no file in a bundle stands in for',
    ],
  };
}

/**
 * A pack, read as a pack.
 *
 * `verifyPack` settles the envelope's key, then the content type, then the signature, then the
 * manifest's own contradictions, then every receipt inside it, then the chain walk. This command
 * forwards what it was handed and reports what comes back, including the two figures of `duty` as the
 * deployment's own statement and never as a verdict: the comparison the format leaves out of a signed
 * pack is left out here too, because whether a duty was owed turns on the mapping a revision names and
 * on the law behind it, which no reader of one container decides.
 */
function readPack(bytes: Uint8Array, inputs: Inputs, kid: Uint8Array): Reading {
  const verified: VerifiedPack = verifyPack(bytes, { resolveKey: resolveEvidence(inputs.evidence) });
  const { manifest, outcome } = verified;
  return {
    contentType: PACK_CONTENT_TYPE,
    reader: 'verifyPack',
    kid: toHex(kid),
    facts: [
      { key: 'signature', label: 'signature', value: 'holds over the envelope, and over every receipt inside it, under designated keys', json: true },
      { key: 'assembledAt', label: 'assembled at', value: `${manifest.at} (${isoOf(manifest.at)})`, json: manifest.at },
      {
        key: 'span',
        label: 'span',
        value: `${manifest.span.from} to ${manifest.span.to}, from included and to excluded (${isoOf(manifest.span.from)} to ${isoOf(manifest.span.to)})`,
        json: manifest.span,
      },
      {
        key: 'chain',
        label: 'chain',
        value: `anchor ${toHex(manifest.chain.anchor)} to head ${toHex(manifest.chain.head)}`,
        json: { anchor: toHex(manifest.chain.anchor), head: toHex(manifest.chain.head) },
      },
      {
        key: 'walked',
        label: 'walked',
        value: `${outcome.walked.length} of ${manifest.items.length} items, from the anchor to the head`,
        json: { walked: outcome.walked.length, declared: manifest.items.length },
      },
      {
        key: 'items',
        label: 'items',
        value: outcome.walked.map((one) => `${one.item.id} at ${one.item.iat}, receipt under ${toHex(one.receipt.header.kid)}`).join('; '),
        json: outcome.walked.map((one) => ({
          id: one.item.id,
          iat: one.item.iat,
          prev: toHex(one.item.prev),
          receiptKid: toHex(one.receipt.header.kid),
          receiptIssuer: one.receipt.payload.iss,
        })),
      },
      {
        key: 'duty',
        label: 'duty',
        value: `${manifest.duty.art}, revision ${manifest.duty.rev} (${isoOf(manifest.duty.rev)}), required ${manifest.duty.required} s, held ${manifest.duty.held} s, both as the deployment states them`,
        json: manifest.duty,
      },
    ],
    notChecked: [
      `whether ${manifest.duty.required} s required is met by ${manifest.duty.held} s held: that comparison belongs to the duty mapping revision ${manifest.duty.rev} names, and this command states both figures and judges neither`,
      'whether these receipts are all the deployment still holds, and whether the span is the period somebody asked for: the walk shows that nothing is missing between the first item and the last, and nothing else',
      'whether this pack agrees with the copy a reader held before, which is the only way a deleted tail becomes visible',
    ],
  };
}

/**
 * An export, read as an export.
 *
 * The export reader takes one pinned key rather than a resolver, so the kid the protected header names
 * selects which designated key the call is made with, and the reader still holds the rule itself: it
 * compares that kid against the digest of the key it was handed before it verifies a byte. An absent
 * designation is refused as the gap in the call that it is, in the code the receipt reader uses for
 * the same state, rather than by offering some other key the caller owns.
 *
 * A companion file is matched by its own name, because that is the name the signed item carries and the
 * format checks it to be a bare one. A file no item names is left unused, and an item whose name was
 * not handed over is refused by that name, because an export that reported on originals nobody put in
 * the reader's hand is the defect this container exists not to have.
 */
function readExport(bytes: Uint8Array, inputs: Inputs, kid: Uint8Array): Reading {
  const key = resolveEvidence(inputs.evidence)(kid);
  if (key === undefined) {
    throw new ReceiptError('UNKNOWN_KEY', `header kid=${toHex(kid)}, which no ${KEY_FLAG} designates`);
  }
  const verified: VerifiedExport = verifyExport(bytes, key, { companions: inputs.companions });
  const { manifest } = verified;
  const collection = manifest.collection;
  const items = collection.k === 'void' ? [] : collection.items;
  return {
    contentType: EXPORT_CONTENT_TYPE,
    reader: 'verifyExport',
    kid: toHex(kid),
    facts: [
      { key: 'signature', label: 'signature', value: 'holds, EdDSA over the Sig_structure an export frames, under the designated key', json: true },
      { key: 'assembledAt', label: 'assembled at', value: `${manifest.at} (${isoOf(manifest.at)})`, json: manifest.at },
      {
        key: 'assessment',
        label: 'assessment',
        value: `${manifest.assessment.k}: ${manifest.assessment.states}`,
        json: manifest.assessment,
      },
      {
        key: 'claim',
        label: 'claim',
        value: `${manifest.claim.kind}, made ${manifest.claim.made} (${isoOf(manifest.claim.made)}) by ${manifest.claim.by}: ${manifest.claim.states}`,
        json: manifest.claim,
      },
      {
        key: 'collection',
        label: 'collection',
        value: collection.k === 'void' ? `void: ${collection.states}` : `${collection.k}, ${items.length} item(s)`,
        json: { kind: collection.k, items: items.length, ...(collection.k === 'void' ? { states: collection.states } : {}) },
      },
      ...(collection.k === 'anchored'
        ? [
            {
              key: 'endpoints',
              label: 'endpoints',
              value: `anchor ${toHex(collection.anchor)}, head ${toHex(collection.head)}, walked to ${String(collection.items.length)} of ${String(collection.items.length)}`,
              json: { anchor: toHex(collection.anchor), head: toHex(collection.head) },
            },
          ]
        : []),
      {
        key: 'originals',
        label: 'originals',
        value:
          items.length === 0
            ? 'none stated'
            : `${String(items.length)} digest(s) recomputed against the bytes this run checked${inputs.companions.size === 0 ? ', none of them from a companion file' : `, ${String(inputs.companions.size)} companion file(s) handed over`}`,
        json: items.map((one) => ({
          id: one.id,
          iat: one.iat,
          sha256: toHex(one.d),
          original: one.orig.k === 'inline' ? 'inline' : one.orig.name,
        })),
      },
    ],
    notChecked: [
      'whether this export is complete at the source it came from: no walk can see a store, which is why the endpoints a reader already has cause to believe are compared by that reader and not invented here',
      `whether ${manifest.at} is recent enough to answer anybody's question, and whether any legal duty attaches to this material: neither is this command's to decide, and no clock and no mapping was passed to it`,
    ],
  };
}

/**
 * A deployment manifest, read as one.
 *
 * `readDeploymentManifest` is the SDK's own rule, the one a client applies to the body a deployment
 * serves, and it is why this command needs no second mechanism for manifest keys: the designated set is
 * handed over in the policy field that holds them, and the three states a manifest can be in,
 * authenticated, refused, and parsed while resting on nothing, come back as that function's answer
 * rather than as a wording this file chose. A run that designated no key is not a run that failed: it
 * asked a narrower question, and the advisory the function writes is printed instead of softened. No
 * line here claims a signature held when none was checked, which is the reason the verdict line this
 * command prints for the other three types is a fact about the envelope rather than a fixed word.
 */
function readManifest(bytes: Uint8Array, inputs: Inputs, kid: Uint8Array): Reading {
  const policy: AshaveriPolicy = {
    manifestKeys: Object.fromEntries(inputs.manifest.map((one) => [one.kid, one.publicKey])),
  };
  const { manifest, authentication } = readDeploymentManifest(bytes, policy);
  const seal = authentication.authenticated
    ? `sealed, and the seal holds under ${String(authentication.kid)}, designated by ${MANIFEST_KEY_FLAG}`
    : (authentication.advisory ?? 'not authenticated, and no reason was recorded');
  return {
    contentType: DEPLOYMENT_MANIFEST_CONTENT_TYPE,
    reader: 'readDeploymentManifest',
    kid: authentication.kid ?? toHex(kid),
    facts: [
      { key: 'seal', label: 'seal', value: seal, json: authentication },
      { key: 'issuer', label: 'issuer', value: manifest.iss, json: manifest.iss },
      { key: 'instance', label: 'instance', value: manifest.ins, json: manifest.ins },
      { key: 'keyEpoch', label: 'key epoch', value: String(manifest.epk), json: manifest.epk },
      {
        key: 'declaredKeys',
        label: 'declared keys',
        value: manifest.keys.map((one) => `${one.kid} (${one.alg})`).join('; '),
        json: manifest.keys,
      },
      {
        key: 'epochs',
        label: 'rotation',
        value:
          manifest.epochs === null
            ? `no key entry names an epoch, so the keys above are the keys of the current epoch ${manifest.epk}`
            : manifest.epochs
                .map((one) => {
                  const end = one.validTo === null ? 'no published end' : String(one.validTo);
                  return `epoch ${one.epoch} from ${one.validFrom} to ${end}, keys ${one.kids.join(', ')}`;
                })
                .join('; '),
        json: manifest.epochs,
      },
      { key: 'models', label: 'models', value: manifest.models.map((one) => `${one.id}@${one.wts}`).join('; '), json: manifest.models },
      { key: 'measurement', label: 'measurement', value: `${manifest.meas.m} (${manifest.meas.tee})`, json: manifest.meas },
    ],
    notChecked: [
      `which of these keys is trusted for anything: no policy document was read and no digest is cited, so the ${String(manifest.keys.length)} declared key(s) are reported as the deployment's own statement about itself`,
      `whether a receipt stamped under one of these epochs was issued inside it: 'ashaveri verify-receipt' adjudicates that, against a policy and a manifest together`,
    ],
  };
}

/**
 * The four types this command can meet, each with the reader that answers for it. The keys are the
 * constants the format package publishes, so a fifth type published beside them reaches this command as
 * an unknown `typ` and is refused by name rather than read as one of these four.
 */
const READERS: ReadonlyMap<string, (bytes: Uint8Array, inputs: Inputs, kid: Uint8Array) => Reading> = new Map([
  [RECEIPT_CONTENT_TYPE, readReceipt],
  [PACK_CONTENT_TYPE, readPack],
  [EXPORT_CONTENT_TYPE, readExport],
  [DEPLOYMENT_MANIFEST_CONTENT_TYPE, readManifest],
]);

/**
 * One named companion file, under the name an export item carries.
 *
 * The basename is the key because the format's own `name` is a bare one, so a handover that keeps an
 * item's originals beside its manifest needs no mapping spelled out: the file called `contract.txt`
 * answers the item naming `contract.txt`. The bytes are then checked against the item's own digest, so
 * a file parked under the right name with the wrong contents is refused by the reader rather than
 * believed. Two files at one name is the same name claimed twice, and the second would answer for the
 * item that carries the first one's bytes, so it is refused as the call it is.
 */
async function companionFiles(paths: readonly string[] | undefined): Promise<ReadonlyMap<string, Uint8Array>> {
  const byName = new Map<string, Uint8Array>();
  for (const path of paths ?? []) {
    const name = basename(path);
    if (name === path || name === '') {
      throw new UsageError(`--companion must name one file, not '${path}': an export item names its original by its bare name, so a path with separators in it answers to nothing`);
    }
    if (byName.has(name)) {
      throw new UsageError(`--companion names '${name}' twice, and the second file would answer for the item carrying the first one's bytes`);
    }
    byName.set(name, await readBytes(path, '--companion'));
  }
  return byName;
}

/**
 * The bytes of exactly one named document, and the one input shape refused on principle.
 *
 * A directory is a bundle, and a bundle arrives under the rules that govern a substituted root: which
 * files stand in it, which are omitted, which are extra, whether a path escapes the root, and whether a
 * replay is stale. None of those is this change. The refusal has to say which of the two it is, because
 * "this tool cannot verify a pack" is false, and a caller left believing it walks away from a command
 * that reads a pack as soon as one is named.
 */
async function readOneDocument(path: string): Promise<Uint8Array> {
  if (path === '-') {
    return readBytes(path, 'document');
  }
  let info;
  try {
    info = await stat(path);
  } catch (err) {
    throw new UsageError(`cannot read document '${path}': ${err instanceof Error ? err.message : String(err)}`);
  }
  if (info.isDirectory()) {
    throw new UsageError(
      `'${path}' is a directory, and this command reads exactly one signed document per run, so name the file inside it. A directory is a bundle, and a bundle is governed by the rules over which files stand in a substituted root, which are omitted, which are extra and whether a replay is stale, which are not what decides a document's type. Nothing about a pack or an export is unreadable here: pass the file itself`,
    );
  }
  if (!info.isFile()) {
    throw new UsageError(`'${path}' is neither a regular file nor stdin, and this command reads exactly one signed document per run`);
  }
  return readBytes(path, 'document');
}

/**
 * Which designations this run was handed, and whether the document in front of it consulted them.
 *
 * A designation that did nothing is reported rather than dropped, and a caller looping this command
 * over a pile is expected to hand both roles to every file, so an unused designation is not a refusal:
 * a receipt key cannot authenticate a manifest and should not have to be left off the command line for
 * that to be true.
 */
function designationFacts(contentType: string, inputs: Inputs): readonly Fact[] {
  const roles: Record<string, string> = {
    [KEY_FLAG]: 'signs, or is named inside, an evidence document',
    [MANIFEST_KEY_FLAG]: 'authenticates a deployment manifest',
  };
  const consultedFor = (keys: readonly DesignatedKey[], consulted: boolean): readonly Fact[] =>
    keys.map((one) => {
      const role = roles[one.source] ?? 'names a key';
      return {
        key: consulted ? 'designated' : 'notConsulted',
        label: consulted ? 'designated' : 'not consulted',
        value: consulted
          ? `${one.kid} = ${one.publicKey} (${one.source}, consulted for ${contentType})`
          : `${one.kid} (${one.source} designates the key that ${role}, and ${contentType} is not authenticated by it)`,
        json: { kid: one.kid, publicKey: one.publicKey, source: one.source, consulted },
      };
    });
  const evidenceConsulted = contentType !== DEPLOYMENT_MANIFEST_CONTENT_TYPE;
  return [
    ...consultedFor(evidenceConsulted ? inputs.evidence : inputs.manifest, true),
    ...consultedFor(evidenceConsulted ? inputs.manifest : inputs.evidence, false),
    {
      key: 'keySource',
      label: 'key source',
      value:
        contentType === DEPLOYMENT_MANIFEST_CONTENT_TYPE
          ? 'no policy document was read and no policy digest is cited, so every key this run trusted a seal against came from the command line'
          : `no policy document was read: the keys ${contentType} is checked against are the ones this command line named, and nothing else`,
      json: null,
    },
  ];
}

function humanReading(reading: Reading, inputs: Inputs): string {
  const field = (one: Fact): string => `  ${`${one.label}:`.padEnd(18)}${one.value}`;
  return [
    `content type:     ${reading.contentType}`,
    '                  label 3 of the COSE_Sign1 protected header, which is inside the signature below',
    `read by:          ${reading.reader}, over the kid ${reading.kid}`,
    ...reading.facts.map(field),
    ...designationFacts(reading.contentType, inputs).map(field),
    ...reading.notChecked.map((one) => `  not checked:      ${one}`),
  ].join('\n');
}

function jsonReading(reading: Reading, inputs: Inputs): Record<string, unknown> {
  return {
    ok: true,
    contentType: reading.contentType,
    contentTypeFrom: 'label 3 of the COSE_Sign1 protected header, inside the signature',
    reader: reading.reader,
    kid: reading.kid,
    document: Object.fromEntries(reading.facts.map((one) => [one.key, one.json])),
    keyDesignations: designationFacts(reading.contentType, inputs).map((one) => one.json),
    notChecked: reading.notChecked,
  };
}

/**
 * One verb of this family, run to its exit code: the pinned verb's own name in the argument refusal, and
 * the pinned content type in the classification that chooses a reader. Everything after that line, the
 * keys, the companions, the readers, the two renderings and the three exit codes, is shared because a
 * narrower question about the same bytes does not change what an answer about them is made of.
 */
export async function runVerifyHandover(
  positionals: string[],
  values: VerifyHandoverFlags,
  pin: VerbPin = HANDOVER_VERB,
): Promise<number> {
  if (positionals.length !== 1) {
    throw new UsageError(`expected exactly one argument: '${pin.verb} <document>'`);
  }
  const path = positionals[0] as string;
  // Refused before a byte is read, the way an argument that is not a key is: a designation that is not a
  // canonical key is a typing mistake, and it is one whoever the document turns out to be.
  const evidence = designatedKeys(values.key, KEY_FLAG);
  const manifestKeys = designatedKeys(values['manifest-key'], MANIFEST_KEY_FLAG);
  const companions = await companionFiles(values.companion);
  const json = values.json === true;
  const inputs: Inputs = { evidence, manifest: manifestKeys, companions };
  const bytes = await readOneDocument(path);

  let contentType: string | null = null;
  try {
    const found = classify(bytes, pin.contentType);
    contentType = found.contentType;
    const reader = READERS.get(contentType);
    if (reader === undefined) {
      // Unreachable by construction, since the classifier answers with a key of this very map. Written
      // anyway, because a report that printed a verdict it had no reader for is the failure this command
      // exists to make impossible, and an assertion here is cheaper than that report.
      throw new ReceiptError('BAD_PROTECTED_HEADER', `typ=${contentType} names no reader this command holds`);
    }
    if (contentType !== DEPLOYMENT_MANIFEST_CONTENT_TYPE && evidence.length === 0) {
      // The call, not the document: a signature is checked against a key the caller designates, and this
      // command trusts nothing it was not handed. A manifest is the one document that can be read
      // without a designation and still say something true about itself, which is why it is asked for
      // one and the others are not.
      throw new UsageError(
        `${KEY_FLAG} is required to verify ${contentType}: its signature is checked against the key its own header designates, and a document that vouched for its own signer would vouch for anything. For ${DEPLOYMENT_MANIFEST_CONTENT_TYPE}, ${MANIFEST_KEY_FLAG} is the flag that designates`,
      );
    }
    const reading = reader(bytes, inputs, found.kid);
    if (json) {
      writeJson(jsonReading(reading, inputs));
    } else {
      process.stdout.write(`${humanReading(reading, inputs)}\n`);
    }
    return 0;
  } catch (err) {
    if (err instanceof ReceiptError || err instanceof SdkError) {
      return refuse(contentType, err, json);
    }
    throw err;
  }
}
