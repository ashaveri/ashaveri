import { sha256 } from '@noble/hashes/sha2.js';
import { ReceiptError } from './errors.js';
import { readJsonBytes, type JsonObject } from './json-text.js';
import { firstForgingCodePoint } from './line-text.js';
import {
  decodeSealedDeploymentManifest,
  isSealedDeploymentManifest,
  verifySealedDeploymentManifest,
} from './manifest-seal.js';
import { PROVENANCES, isProvenance, type Provenance } from './provenance.js';

/**
 * The model inventory record: a deployment's inventory of the models it ran, beside the receipts that
 * attest them and the signed manifest that binds them.
 *
 * A receipt attests one response and names the model and weights digest it was produced under; the
 * deployment manifest declares which models the deployment serves and signs that declaration. Neither
 * document says what a model is for, what risk category the deployment places it in, or when it was last
 * reviewed, and an audit dossier asks for exactly those things beside the cryptographically bound facts.
 * This record states them together, and keeps the two kinds of statement apart: a field the manifest
 * binds is copied from the manifest and checked against it, and a field the deployment asserts is the
 * deployment's own word, which nothing in this record proves. The split is the layout's, not a label a
 * writer picks: `bound` and `asserted` are the two blocks a parsed model entry carries, and which wire
 * member lands in which block is fixed below.
 *
 * It carries no signature, as the disclosure record and the retention manifest carry none: its trust
 * arrives from whoever hands it over beside the receipts it speaks of. The export container is what
 * carries it as evidence, the record's bytes riding an item's inline original under the export's own
 * signature, and the manifest's signature is what grounds the bound fields. So the reader has two doors.
 * `parseModelInventory` answers the layout with no manifest in hand, and labels every field by the block
 * it belongs to; a reviewer holding only the record sees which fields are bound and which are asserted,
 * and sees that the bound ones are claims about a manifest this record designates by digest.
 * `verifyModelInventory` is handed that manifest's bytes, hashes them against the designation, reads the
 * positions the bound fields are copied from, and refuses any disagreement by name. A bound field that
 * fails the comparison is the record contradicting the manifest it designates; an asserted field has no
 * comparison to fail, which is the whole difference between the two, and a mutation of one is refused
 * while a mutation of the other is read.
 *
 * The manifest document is read openly here, and that is the manifest's own rule rather than a looseness
 * of this reader: version 1 of that layout leaves a member it does not name alone, so the extraction
 * below reads `iss`, `ins` and `models[]` and nothing else, and a manifest carrying members this
 * extraction does not know is still the manifest the deployment signed. The document's own reader is
 * `parseManifest` in `@ashaveri/sdk`, which answers the whole layout; this module asks only the three
 * questions its bound fields turn on, and a manifest those three positions cannot be read out of is
 * refused as unreadable rather than guessed at. The seal is answered with the envelope reader this
 * package publishes, and authenticated only when the caller designates a key: the outcome states
 * `sealed` and `authenticated` apart, so a reading that checked the digest but not the signature never
 * reports an authentication it did not do.
 *
 * The pointers are a closed registry of provisions an inventory extract may answer, each a pointer for
 * counsel rather than a conclusion, the same split the disclosure record's duty pointers state. Whether
 * a provision applies to a deployment, or was met by what it ran, is a judgment this layout does not
 * make, and the limits sentence every record carries says so in the format's own words.
 */

/** The versions this module reads, and the only place an inventory version is asked. */
export const MODEL_INVENTORY_VERSIONS: readonly number[] = [1];

/** The members of the one layout, in the order the writer emits them and the spec publishes them. */
export const MODEL_INVENTORY_V1_MEMBERS = ['v', 'prov', 'at', 'scope', 'manifest', 'models', 'pointers', 'limits'] as const;
export const MODEL_INVENTORY_MANIFEST_MEMBERS = ['sha256', 'iss', 'ins'] as const;
export const MODEL_INVENTORY_MODEL_MEMBERS = ['id', 'wts', 'version', 'purpose', 'risk', 'reviews'] as const;
export const MODEL_INVENTORY_REVIEW_MEMBERS = ['at', 'by'] as const;

/**
 * The two blocks a model entry splits into, and the wire members each holds. The split is the layout's
 * answer to the rule that asserted context and cryptographically bound facts stay distinguishable:
 * `id` and `wts` are what the manifest's `models[]` declares and signs, so they
 * are bound; `version`, `purpose`, `risk` and `reviews` are what the deployment states about a model the
 * manifest names, and no signature covers them, so they are asserted. A writer cannot move a member
 * between the blocks, because the blocks are not on the wire: the wire carries the six members flat, and
 * the reader groups them by this rule.
 */
export const MODEL_INVENTORY_BOUND_MODEL_FIELDS = ['id', 'wts'] as const;
export const MODEL_INVENTORY_ASSERTED_MODEL_FIELDS = ['version', 'purpose', 'risk', 'reviews'] as const;

/**
 * The pointers the layout enumerates, each naming one provision an inventory extract may answer. The
 * citations beside them are the instruments as the estate's own sources name them; they are pointers
 * for counsel to weigh, not conclusions about applicability, and the record's limits sentence says so.
 * The registry is closed at these three provisions. An Australia APP 1.7-1.9 automated-decision
 * inventory extract reads the captured APP instrument text; this version enumerates no APP pointer and
 * states no APP period or citation.
 */
export const MODEL_INVENTORY_POINTERS = ['osfi-e23-app-1', 'mas-airg', 'naic-3-3'] as const;

export type ModelInventoryPointer = (typeof MODEL_INVENTORY_POINTERS)[number];

/** The citation each pointer names, in the order the registry declares them. */
export const MODEL_INVENTORY_POINTER_CITATIONS: Readonly<Record<ModelInventoryPointer, string>> = {
  'osfi-e23-app-1': 'OSFI E-23 (model risk management guideline), Appendix 1',
  'mas-airg': 'MAS AIRG (AI Risk Management guidelines)',
  'naic-3-3': 'NAIC 3.3 (model bulletin / governance guidance)',
};

/**
 * The limits every record states, verbatim. The format owns this sentence rather than the writer: a
 * record whose limits member says anything else is refused, because the one thing a reader of an
 * inventory extract must not have to weigh is whether the record's own account of its limits is true.
 */
export const MODEL_INVENTORY_LIMITS =
  'This record is an inventory extract, not a legal determination. Its bound fields are copied from the ' +
  'deployment manifest it designates and are checked against that manifest when a reader is handed it; ' +
  'its asserted fields are the deployment\'s own statements, which nothing in this record proves. The ' +
  'pointers name provisions for counsel to weigh, not conclusions that a duty applies or was met. A ' +
  'record labeled fixture describes fixture material and no live deployment.';

/**
 * The width one authored text member of this layout may hold, in UTF-16 units of the text as this
 * package holds it. The scope and the purpose are the longest things a record states; the copied
 * positions carry no ceiling, for the reason the epoch inventory gives beside its own copied ids: a
 * ceiling here would refuse an inventory over a manifest the deployment published.
 */
export const MODEL_INVENTORY_TEXT_MAX_UNITS = 400;

/** One review the deployment states about a model: when it happened and who did it. */
export interface ModelInventoryReview {
  readonly at: number;
  readonly by: string;
}

/** The fields the manifest binds: the model's identity and the digest of its weights. */
export interface ModelInventoryBound {
  readonly id: string;
  readonly wts: string;
}

/** The fields the deployment asserts about a model the manifest names. */
export interface ModelInventoryAsserted {
  readonly version: string;
  readonly purpose: string;
  readonly risk: string;
  readonly reviews: readonly ModelInventoryReview[];
}

/** One model of the inventory, split into the two kinds of statement the layout keeps apart. */
export interface ModelInventoryModel {
  readonly bound: ModelInventoryBound;
  readonly asserted: ModelInventoryAsserted;
}

/** The manifest the record designates, by the digest of its exact bytes, beside the identity it binds. */
export interface ModelInventoryManifestRef {
  readonly sha256: string;
  readonly iss: string;
  readonly ins: string;
}

/** A model inventory record at version 1: the whole layout, every member required. */
export interface ModelInventoryRecord {
  readonly v: 1;
  readonly prov: Provenance;
  /** The assembly stamp: the extract's date, in unix seconds. */
  readonly at: number;
  /** What the extract covers, in the deployment's own words. */
  readonly scope: string;
  readonly manifest: ModelInventoryManifestRef;
  readonly models: readonly ModelInventoryModel[];
  readonly pointers: readonly ModelInventoryPointer[];
  /** The format's limits sentence, verbatim; the reader refuses any other text at this position. */
  readonly limits: string;
}

/**
 * What a caller hands the verifying door beside the record: the exact manifest bytes the record
 * designates, sealed or plain, and optionally the key the manifest's seal is authenticated under. The
 * reader resolves nothing: the bytes arrive as an argument, and a caller holding only the record reads
 * it through `parseModelInventory` instead.
 */
export interface ModelInventoryVerifyOptions {
  readonly manifestBytes: Uint8Array;
  readonly manifestPublicKey?: Uint8Array;
}

export interface VerifiedModelInventory {
  readonly record: ModelInventoryRecord;
  /** What the reader did about the manifest's seal: whether it was sealed, and whether a key authenticated it. */
  readonly manifest: { readonly sealed: boolean; readonly authenticated: boolean };
}

const text = new TextEncoder();

function bad(detail: string): ReceiptError {
  return new ReceiptError('MODEL_INVENTORY_BAD_DOCUMENT', detail);
}

function readMap(value: unknown, position: string): JsonObject {
  if (!(value instanceof Map)) throw bad(`${position} is not an object`);
  return value;
}

/**
 * Text this record copies out of the manifest: a string, not an empty one, and carrying no character of
 * the printed-line class. No ceiling and no padding rule, for the epoch inventory's reason: the manifest
 * declares a minimum length for its ids and no maximum, and a narrowing on this side would refuse an
 * inventory over a manifest the deployment published. The class is asked because these values are
 * printed beside the models they name, and a character that ends, hides or reorders a row makes the line
 * a reader sees stop being the bytes the manifest signed.
 */
function requireCopiedText(value: unknown, position: string): string {
  if (typeof value !== 'string' || text.encode(value).length < 1) {
    throw bad(`${position} must be a non-empty text`);
  }
  const forging = firstForgingCodePoint(value);
  if (forging !== undefined) {
    throw bad(`${position} carries the character U+${forging.toString(16).toUpperCase().padStart(4, '0')}, which forges the line it is printed on`);
  }
  return value;
}

/**
 * Text the deployment authors: the same class, beside the width this layout states and the padding rule
 * a printed row keeps. The scope and the purpose are prose; the version, the risk category and a
 * review's author are labels the deployment chooses, and all of them are printed, so one rule reads
 * them all.
 */
function requireAuthoredText(value: unknown, position: string): string {
  const label = requireCopiedText(value, position);
  if (label.length > MODEL_INVENTORY_TEXT_MAX_UNITS) {
    throw bad(`${position} is wider than the ${String(MODEL_INVENTORY_TEXT_MAX_UNITS)} units this layout holds`);
  }
  if (label.trim() !== label) {
    throw bad(`${position} carries leading or trailing space, which a printed row does not carry`);
  }
  return label;
}

/** A digest, stated the way this estate states every one of them: sixty-four lowercase hex characters. */
function requireDigest(value: unknown, position: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw bad(`${position} must be sixty-four lowercase hex characters`);
  }
  return value;
}

/** A unix second: a whole number no smaller than zero, the integer spelling already settled by the reading. */
function requireStamp(value: unknown, position: string): number {
  if (typeof value !== 'number' || value < 0) {
    throw bad(`${position} must be a whole number of unix seconds no smaller than zero`);
  }
  return value;
}

/** The closure rule: a member the layout does not define makes the document malformed, not read around. */
function assertDefined(raw: JsonObject, members: readonly string[], where: string): void {
  for (const key of raw.keys()) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw bad(`${where} carries a member this version does not define: ${JSON.stringify(String(key))}`);
    }
  }
}

function readReviews(value: unknown, at: number, position: string): readonly ModelInventoryReview[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw bad(`${position} must be a non-empty array: a model with no review states nothing about its review`);
  }
  return value.map((one, index): ModelInventoryReview => {
    const site = `${position}[${String(index)}]`;
    const raw = readMap(one, site);
    assertDefined(raw, MODEL_INVENTORY_REVIEW_MEMBERS, site);
    const reviewAt = requireStamp(raw.get('at'), `${site}.at`);
    // A review stamped after the extract that carries it is another document's review, the same rule
    // the export's claim states beside the assembly stamp: both instants are inside one record, so a
    // disagreement is the record contradicting itself.
    if (reviewAt > at) {
      throw bad(`${site}.at=${String(reviewAt)} postdates the extract's assembly stamp at=${String(at)}`);
    }
    return { at: reviewAt, by: requireAuthoredText(raw.get('by'), `${site}.by`) };
  });
}

function readModels(value: unknown, at: number): readonly ModelInventoryModel[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw bad('models must be a non-empty array: an inventory of no models states nothing about what ran');
  }
  const named = new Set<string>();
  return value.map((one, index): ModelInventoryModel => {
    const site = `models[${String(index)}]`;
    const raw = readMap(one, site);
    assertDefined(raw, MODEL_INVENTORY_MODEL_MEMBERS, site);
    const id = requireCopiedText(raw.get('id'), `${site}.id`);
    if (named.has(id)) {
      throw bad(`models names ${JSON.stringify(id)} twice, so one model is stated twice and its two entries cannot both be read`);
    }
    named.add(id);
    return {
      bound: { id, wts: requireDigest(raw.get('wts'), `${site}.wts`) },
      asserted: {
        version: requireAuthoredText(raw.get('version'), `${site}.version`),
        purpose: requireAuthoredText(raw.get('purpose'), `${site}.purpose`),
        risk: requireAuthoredText(raw.get('risk'), `${site}.risk`),
        reviews: readReviews(raw.get('reviews'), at, `${site}.reviews`),
      },
    };
  });
}

function readPointers(value: unknown): readonly ModelInventoryPointer[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw bad('pointers must be a non-empty array: an extract states which provisions it answers');
  }
  const named = new Set<string>();
  return value.map((one, index): ModelInventoryPointer => {
    const site = `pointers[${String(index)}]`;
    if (typeof one !== 'string') throw bad(`${site} must be a text pointer label`);
    if (!(MODEL_INVENTORY_POINTERS as readonly string[]).includes(one)) {
      throw new ReceiptError(
        'MODEL_INVENTORY_UNKNOWN_POINTER',
        `${site} names ${JSON.stringify(one)}, outside the pointers the layout enumerates`,
      );
    }
    if (named.has(one)) {
      throw bad(`pointers names ${JSON.stringify(one)} twice`);
    }
    named.add(one);
    return one as ModelInventoryPointer;
  });
}

/**
 * A model inventory record, out of the bytes of the file as it sits on the volume.
 *
 * The reading is the strict one the retention manifest and the epoch inventory use, through the same
 * JSON scanner and for the same two reasons: a member named twice would be settled by `JSON.parse` into
 * whichever value the parser reached last while the bytes carry both, and a float wearing an integer
 * arrives at a check as the very number it imitates. The version is asked before any member is read,
 * because which member list applies is the one question a wrong version cannot be talked out of.
 */
export function parseModelInventory(bytes: Uint8Array): ModelInventoryRecord {
  const raw = readJsonBytes(bytes, (detail) => {
    throw bad(detail);
  });
  const document = readMap(raw, 'record');
  const version = document.get('v');
  if (typeof version !== 'number') {
    throw bad('v must be an integer model inventory version');
  }
  if (!MODEL_INVENTORY_VERSIONS.includes(version)) {
    throw new ReceiptError(
      'MODEL_INVENTORY_UNSUPPORTED_VERSION',
      `model inventory version ${String(version)} is not a layout this package reads`,
    );
  }
  assertDefined(document, MODEL_INVENTORY_V1_MEMBERS, 'record');
  const prov = document.get('prov');
  if (!isProvenance(prov)) {
    throw bad(`prov must be one of ${PROVENANCES.map((one) => `'${one}'`).join(', ')}, got ${typeof prov === 'string' ? `'${prov}'` : String(prov)}`);
  }
  const at = requireStamp(document.get('at'), 'at');
  const manifest = readMap(document.get('manifest'), 'manifest');
  assertDefined(manifest, MODEL_INVENTORY_MANIFEST_MEMBERS, 'manifest');
  const limits = document.get('limits');
  if (limits !== MODEL_INVENTORY_LIMITS) {
    throw bad('limits must state the limits sentence this format owns, verbatim; a record does not word its own limits');
  }
  return {
    v: 1,
    prov,
    at,
    scope: requireAuthoredText(document.get('scope'), 'scope'),
    manifest: {
      sha256: requireDigest(manifest.get('sha256'), 'manifest.sha256'),
      iss: requireCopiedText(manifest.get('iss'), 'manifest.iss'),
      ins: requireCopiedText(manifest.get('ins'), 'manifest.ins'),
    },
    models: readModels(document.get('models'), at),
    pointers: readPointers(document.get('pointers')),
    limits,
  };
}

/**
 * The record as a file: two-space indented, newline terminated, in the member order the layout declares.
 * The wire carries each model's six members flat, in the order `MODEL_INVENTORY_MODEL_MEMBERS` states,
 * because the bound/asserted split is the reader's grouping and not a shape the writer chooses. The
 * bytes are what an export item digests and a reviewer hashes, so one record state has to produce one
 * byte string, and a writer that emitted the caller's key order would give two writers of one state two
 * digests.
 */
export function encodeModelInventory(record: ModelInventoryRecord): Uint8Array {
  const document: Record<string, unknown> = {
    v: record.v,
    prov: record.prov,
    at: record.at,
    scope: record.scope,
    manifest: { sha256: record.manifest.sha256, iss: record.manifest.iss, ins: record.manifest.ins },
    models: record.models.map((one) => ({
      id: one.bound.id,
      wts: one.bound.wts,
      version: one.asserted.version,
      purpose: one.asserted.purpose,
      risk: one.asserted.risk,
      reviews: one.asserted.reviews.map((review) => ({ at: review.at, by: review.by })),
    })),
    pointers: [...record.pointers],
    limits: record.limits,
  };
  return text.encode(`${JSON.stringify(document, null, 2)}\n`);
}

/**
 * The bytes this writer would produce for a record, run back through this module's own reader before a
 * caller files them beside the receipts they speak of. A deployment cannot hand over a record its own
 * reader refuses, which is the same promise `disclosureRecordBytes` makes: the refusal arrives where the
 * bytes are made rather than at a reviewer holding them later.
 */
export function modelInventoryBytes(record: ModelInventoryRecord): Uint8Array {
  const bytes = encodeModelInventory(record);
  parseModelInventory(bytes);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (one) => one.toString(16).padStart(2, '0')).join('');
}

/**
 * The three positions the bound fields are read from, out of the manifest payload the designation
 * names. The reading is open: the manifest document leaves a member version 1 does not name alone, so
 * this extraction reads `iss`, `ins` and `models[]` and walks past everything else. A position it does
 * read that is absent or ill-shaped makes the manifest unreadable for this purpose, which is a finding
 * about the bytes handed over rather than about the record: the record may be whole and the manifest
 * simply not state what its bound fields claim.
 */
function readManifestBinding(payloadBytes: Uint8Array): { iss: string; ins: string; models: Map<string, string> } {
  const unreadable = (detail: string): ReceiptError =>
    new ReceiptError('MODEL_INVENTORY_MANIFEST_UNREADABLE', detail);
  const raw = readJsonBytes(payloadBytes, (detail) => {
    throw unreadable(detail);
  });
  if (!(raw instanceof Map)) throw unreadable('the manifest payload is not a JSON object');
  const document = raw as JsonObject;
  const iss = document.get('iss');
  const ins = document.get('ins');
  if (typeof iss !== 'string' || iss.length === 0) throw unreadable('the manifest states no issuer to bind the provider to');
  if (typeof ins !== 'string' || ins.length === 0) throw unreadable('the manifest states no instance to bind the deployment to');
  const modelsRaw = document.get('models');
  if (!Array.isArray(modelsRaw) || modelsRaw.length === 0) {
    throw unreadable('the manifest states no models to bind the inventory to');
  }
  const models = new Map<string, string>();
  for (const [index, one] of (modelsRaw as unknown[]).entries()) {
    if (!(one instanceof Map)) throw unreadable(`models[${String(index)}] is not an object`);
    const entry = one as JsonObject;
    const id = entry.get('id');
    const wts = entry.get('wts');
    if (typeof id !== 'string' || id.length === 0) throw unreadable(`models[${String(index)}].id is not a non-empty text`);
    if (typeof wts !== 'string' || !/^[0-9a-f]{64}$/u.test(wts)) {
      throw unreadable(`models[${String(index)}].wts is not sixty-four lowercase hex characters`);
    }
    if (models.has(id)) throw unreadable(`the manifest declares the model ${JSON.stringify(id)} twice`);
    models.set(id, wts);
  }
  return { iss, ins, models };
}

/**
 * Verify a record against the manifest it designates: the layout, the designation's digest, the seal
 * when a key is designated, and every bound field against the manifest's own statement.
 *
 * The order is what keeps the report honest. The record is parsed first, because a document that
 * contradicts its own layout does so whoever handed it over. The digest comes next: bytes that are not
 * the ones the record designates are another manifest, and reading bound fields out of them would be
 * comparing the record against a document it never named. The seal is answered before the payload is
 * read, and a designated key beside a plain manifest is refused rather than quietly ignored: a caller
 * that named who may sign the manifest has stated a demand, and an unsigned document does not meet it.
 * The comparison itself is per field and names both values, because a bound field that disagrees is the
 * record contradicting the manifest, and which of the two an operator has to look at is the finding.
 *
 * What this does not answer is stated by what it returns. The manifest's own validity beyond the seal
 * (its keys, its epochs, its measurement) is `parseManifest`'s question in the SDK, and the receipts'
 * agreement with the manifest is the reader of those receipts' question; this door answers the record
 * against the manifest's model declaration and nothing else. An asserted field is never compared,
 * because there is nothing signed to compare it to: that is the split the layout exists to keep.
 */
export function verifyModelInventory(bytes: Uint8Array, options: ModelInventoryVerifyOptions): VerifiedModelInventory {
  const record = parseModelInventory(bytes);
  const designated = toHex(sha256(options.manifestBytes));
  if (designated !== record.manifest.sha256) {
    throw new ReceiptError(
      'MODEL_INVENTORY_MANIFEST_MISMATCH',
      `the record designates ${record.manifest.sha256} and the manifest handed over hashes to ${designated}`,
    );
  }
  const sealed = isSealedDeploymentManifest(options.manifestBytes);
  let payloadBytes: Uint8Array;
  let authenticated = false;
  if (sealed) {
    if (options.manifestPublicKey !== undefined) {
      payloadBytes = verifySealedDeploymentManifest(options.manifestBytes, options.manifestPublicKey).payloadBytes;
      authenticated = true;
    } else {
      payloadBytes = decodeSealedDeploymentManifest(options.manifestBytes).payloadBytes;
    }
  } else {
    if (options.manifestPublicKey !== undefined) {
      throw new ReceiptError(
        'MODEL_INVENTORY_MANIFEST_UNSEALED',
        'a manifest signing key was designated and the manifest handed over is the plain document',
      );
    }
    payloadBytes = options.manifestBytes;
  }
  const binding = readManifestBinding(payloadBytes);
  const disagrees = (position: string, stated: string, bound: string): ReceiptError =>
    new ReceiptError(
      'MODEL_INVENTORY_BOUND_DISAGREES',
      `${position} states ${JSON.stringify(stated)} and the designated manifest binds ${JSON.stringify(bound)}`,
    );
  if (record.manifest.iss !== binding.iss) throw disagrees('manifest.iss', record.manifest.iss, binding.iss);
  if (record.manifest.ins !== binding.ins) throw disagrees('manifest.ins', record.manifest.ins, binding.ins);
  for (const [index, model] of record.models.entries()) {
    const wts = binding.models.get(model.bound.id);
    if (wts === undefined) {
      throw new ReceiptError(
        'MODEL_INVENTORY_BOUND_DISAGREES',
        `models[${String(index)}].id names ${JSON.stringify(model.bound.id)}, which the designated manifest does not declare`,
      );
    }
    if (model.bound.wts !== wts) {
      throw disagrees(`models[${String(index)}].wts`, model.bound.wts, wts);
    }
  }
  return { record, manifest: { sealed, authenticated } };
}