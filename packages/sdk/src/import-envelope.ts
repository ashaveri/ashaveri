import { ReceiptError } from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { fromBase64Url, toBase64Url, toHex } from './b64.js';
import { SdkError, type SdkErrorCode } from './errors.js';
import {
  IMPORT_TRANSFORMATION,
  normalizeProviderExport,
  type ImportNormalization,
  type ImportReportRow,
} from './import-normalize.js';

/**
 * The import envelope, and the reader that refuses the ways it can be faked.
 *
 * A provider hands over an export: one document, signed by the provider, about what it served. The
 * envelope is this estate's record of that export as imported, and it exists for one reason. Somebody
 * will read the export into a normalized view sooner or later, and the moment that view is written
 * beside the export without a label, a reader of the pair cannot tell which of the two a provider's
 * signature covered. So the record holds both and says which is which: the export's exact bytes, held
 * as they arrived and handed back as they arrived, and the derived representations the estate's named
 * rules produced from them, each labeled, each naming the rule that produced it, and each naming the
 * digest of the original it was derived from.
 *
 * Two properties arrange the rest.
 *
 * An original is never re-encoded. The bytes the provider served are stored as they arrived and handed
 * back as they arrived: nothing between those two points decodes them, reformats them, or takes their
 * framing apart and writes it out again. A derived representation that passed through the estate's
 * rules is a derived representation, and it says so; the original keeps standing for itself.
 *
 * Importing the same export twice produces one record. `importEnvelopeKey` is a digest of the record's
 * content, which is the version, the provider it names and the original it holds; the intake stamp in
 * `imported` and the representations in `derived` are not in it, because a second intake of one export
 * dates itself and derives the same view, and a store keyed by this digest holds one record rather than
 * two. That is the one place this contract departs from the capture record's keying, and it is the
 * point of this record rather than an accident: a capture is keyed by everything it states, including
 * when it was taken in, because two captures of one instant are two observations; an import is keyed by
 * what it is about, because the unit's own row asks that one paid-scope export imported twice is one
 * record.
 *
 * Nothing here holds a credential, speaks to a provider or routes anything. The adapter that carries a
 * real provider's export to this shape, and the credential it would hold, belong to the Confidential and
 * Secret halves of this unit and to no artifact of this package; what is published is the record a
 * stranger reads, the reading they run, and the name a store keys on.
 */

/** The one import format version this module reads. An envelope names its own, and never inherits this one. */
export const IMPORT_FORMAT_VERSION = 1;

const IMPLEMENTED_IMPORT_VERSIONS: readonly number[] = [IMPORT_FORMAT_VERSION];

/**
 * Which derived representations this version defines, the whole closed set written once as a list.
 *
 * Exported because the list is one of two statements of this set and the other is a published document:
 * `derived[].k`'s `enum` in `packages/sdk/schemas/import-v1.schema.json` is what an importer outside this
 * repository builds a writer against, and a kind added to one side alone is a document the schema
 * refuses while the reader accepts it. `test/import-envelope.test.ts` reads both spellings and refuses
 * the disagreement in either direction.
 */
export const DERIVED_REPRESENTATION_KINDS = ['normalized-export'] as const;

/** The kinds above as a type, so the set is named in one place and read in two. */
export type ImportDerivedKind = (typeof DERIVED_REPRESENTATION_KINDS)[number];

/**
 * Which transformations a derived representation may name, which is the rule set this version implements.
 * One name, because one normalized view is what version one defines; a second reading of a provider export
 * arrives as a new representation kind and a new version rather than as a second name in this list, since
 * a reader that met an unknown name would have to guess which document it was handed.
 */
export const IMPORT_TRANSFORMATIONS = [IMPORT_TRANSFORMATION] as const;

/** The transformations above as a type. */
export type ImportTransformation = (typeof IMPORT_TRANSFORMATIONS)[number];

/** A derived representation: bytes the estate's rules produced, labeled with the rule and the original they rest on. */
export interface ImportDerivedRepresentation {
  /** Which representation this is, of the kinds this version defines. */
  readonly k: ImportDerivedKind;
  /** The named transformation that produced these bytes, which this package ships and a reader re-runs. */
  readonly derivedBy: ImportTransformation;
  /** sha256 of the original bytes this representation was derived from, so the relationship names its source. */
  readonly basis: string;
  /** The representation's bytes, unpadded base64url, as the transaction produced them. */
  readonly bytes: string;
  /** sha256 of exactly those bytes, recomputed by a reader and never read off this member. */
  readonly sha256: string;
  /** How many bytes `bytes` decodes to. */
  readonly byteCount: number;
}

/** The record: one provider export as imported, held whole beside the representations derived from it. */
export interface ImportEnvelope {
  readonly v: number;
  /** Who the export is from, in the provider's own words as the export states them. */
  readonly provider: {
    /** The provider's name for itself, read off the export's own `provider` member. */
    readonly name: string;
    /** The provider's own name for this export, read off `export_id`. */
    readonly exportId: string;
  };
  /** The provider's bytes, as they arrived and as they are handed back. */
  readonly original: {
    /** Unpadded base64url, in the one spelling that decodes back to these bytes. */
    readonly bytes: string;
    readonly sha256: string;
    readonly byteCount: number;
    /**
     * Our assertion that the provider signed these bytes. A claim, and this record carries no field that
     * could hold the other half of it: a provider's signature travels inside the export's own framing, is
     * read by the adapter's rules rather than by this package, and nothing here states a verdict about it.
     */
    readonly signedByProvider: boolean;
  };
  /** When the bytes came into our hands, on our clock. Never part of the record's identity: see `importEnvelopeKey`. */
  readonly imported: {
    readonly at: number;
  };
  /** The representations the normalization produced, each labeled and each naming its rule and its original. */
  readonly derived: readonly ImportDerivedRepresentation[];
}

/**
 * What a reading concluded, in the two halves that must never be merged.
 *
 * `stated` is the record's claim: which provider it names, when the intake happened, whom it says signed
 * the bytes, and which derived representations it holds. `repeated` is what the reader established for
 * itself: the stored bytes handed back unchanged, the digest this reader computed over them, and the
 * digest the shipped rules produce from them, which every derived row has to state. `report` is the
 * deterministic reading of the unchanged export: every position no rule reads and every position a rule
 * reads that the export states nothing at.
 */
export interface ImportReading {
  readonly stated: {
    readonly provider: { readonly name: string; readonly exportId: string };
    readonly importedAt: number;
    readonly signedByProvider: boolean;
    readonly derived: readonly ImportDerivedRepresentation[];
  };
  readonly repeated: {
    /** The stored bytes, handed back exactly as the record holds them. Never re-encoded, never re-framed. */
    readonly originalBytes: Uint8Array;
    /** The digest this reader computed over those bytes: the record's own statement, recomputed. */
    readonly sha256: string;
    /** The digest of the bytes the shipped normalization produces from the original, which every derived row states. */
    readonly normalizedSha256: string;
  };
  /** The report the rules give this export, recomputed here and never read off the record. */
  readonly report: readonly ImportReportRow[];
}

const HEX64 = /^[0-9a-f]{64}$/;

function refused(code: SdkErrorCode, message: string): never {
  throw new SdkError(code, message);
}

function describe(value: unknown): string {
  if (typeof value === 'string') return `'${value}'`;
  if (value === undefined) return 'absent';
  if (value === null) return 'null';
  return `a ${Array.isArray(value) ? 'list' : typeof value}`;
}

function requireObject(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return refused('NOT_IMPORT_ENVELOPE', `${where} is ${describe(value)}, which is not a member block of an import envelope`);
  }
  return value as Record<string, unknown>;
}

/**
 * Closure, stated the way the capture contract states it: a member the version a document names does not
 * define makes the document invalid rather than a document read with the member dropped. The reason is
 * the same here as there: a writer that stated a field this reader does not know was answering a question
 * this record cannot ask, and dropping it quietly turns that answer into a silence.
 */
function requireKnownMembers(raw: Record<string, unknown>, allowed: readonly string[], where: string): void {
  for (const member of Object.keys(raw)) {
    if (!allowed.includes(member)) {
      refused(
        'NOT_IMPORT_ENVELOPE',
        `${where} carries '${member}', which import version ${String(IMPORT_FORMAT_VERSION)} does not define`,
      );
    }
  }
}

function requireText(raw: Record<string, unknown>, key: string, where: string): string {
  const value = raw[key];
  if (typeof value !== 'string' || value.length === 0) {
    refused('NOT_IMPORT_ENVELOPE', `${where}.${key} is ${describe(value)}, and an envelope has to name it`);
  }
  return value;
}

function requireWhole(raw: Record<string, unknown>, key: string, where: string, what: string): number {
  const value = raw[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    refused('NOT_IMPORT_ENVELOPE', `${where}.${key} is ${describe(value)}, and ${what} is a non-negative whole number`);
  }
  return value;
}

function requireBoolean(raw: Record<string, unknown>, key: string, where: string): boolean {
  const value = raw[key];
  if (typeof value !== 'boolean') {
    refused(
      'NOT_IMPORT_ENVELOPE',
      `${where}.${key} is ${describe(value)}: this record states it either way rather than leaving it out`,
    );
  }
  return value;
}

function requireDigest(raw: Record<string, unknown>, key: string, where: string): string {
  const value = raw[key];
  if (typeof value !== 'string' || !HEX64.test(value)) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where}.${key} is ${describe(value)}, and a digest is 64 lowercase hex characters`);
  }
  return value;
}

/**
 * The version the envelope names, against the versions this module reads.
 *
 * The element of the list, and not the number the document named: the lookup is at once the refusal test
 * and the witness that what comes back is one of the versions this reader implements, which is why no
 * caller of it has to narrow a returned number against the list a second time. A version outside the list
 * is refused rather than read as the nearest one inside it, under the code the capture reader answers the
 * same question with: the version decides which members exist, so a reader with no rules for a version
 * refuses rather than reading it under the rules it does have.
 */
function requireImplementedVersion(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new ReceiptError('UNSUPPORTED_VERSION', `import envelope names ${describe(value)} where a version number belongs`);
  }
  const stated = IMPLEMENTED_IMPORT_VERSIONS.find((each) => each === value);
  if (stated === undefined) {
    throw new ReceiptError(
      'UNSUPPORTED_VERSION',
      `import envelope names version ${String(value)}, and this reader implements ${IMPLEMENTED_IMPORT_VERSIONS.join(', ')} and does not read it as one of them`,
    );
  }
  return stated;
}

interface StatedBytes {
  readonly bytes: string;
  readonly sha256: string;
  readonly byteCount: number;
}

/**
 * The bytes a record or one of its derived representations states, checked three ways before anything
 * reads them.
 *
 * The spelling comes first, and it is the check a JSON validator cannot make, for the reason the capture
 * contract gives: unpadded base64url has more than one spelling for the same bytes whenever the last
 * group is short, and two records of one import written that way would disagree about the record while
 * agreeing about everything in it. The count and the digest are then computed over what decoded, which
 * is where a re-encoded original is caught: a purported equivalent, the same structure written out by a
 * different encoder, decodes to bytes that hash to something else.
 */
function decodeStated(stated: StatedBytes, where: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(stated.bytes);
  } catch (err) {
    return refused(
      'NOT_IMPORT_ENVELOPE',
      `${where} holds ${err instanceof Error ? err.message : String(err)} where bytes belong`,
    );
  }
  if (toBase64Url(bytes) !== stated.bytes) {
    refused(
      'NOT_IMPORT_ENVELOPE',
      `${where} is spelled in a base64url form this reader does not write, so somebody wrote it with another encoder`,
    );
  }
  if (bytes.length !== stated.byteCount) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where} states ${String(stated.byteCount)} bytes and carries ${String(bytes.length)}`);
  }
  const computed = toHex(sha256(bytes));
  if (computed !== stated.sha256) {
    refused('EVIDENCE_DIGEST_MISMATCH', `${where} states ${stated.sha256} and these bytes hash to ${computed}`);
  }
  return bytes;
}

/** Whether a string the document named itself with is one of the representation kinds above. */
function isDerivedKind(value: unknown): value is ImportDerivedKind {
  return typeof value === 'string' && (DERIVED_REPRESENTATION_KINDS as readonly string[]).includes(value);
}

/** Whether a string names one of the transformations above. */
function isTransformation(value: unknown): value is ImportTransformation {
  return typeof value === 'string' && (IMPORT_TRANSFORMATIONS as readonly string[]).includes(value);
}

function readDerived(value: unknown, where: string): ImportDerivedRepresentation {
  const raw = requireObject(value, where);
  requireKnownMembers(raw, ['k', 'derivedBy', 'basis', 'bytes', 'sha256', 'byteCount'], where);
  const k = raw['k'];
  if (!isDerivedKind(k)) {
    refused(
      'NOT_IMPORT_ENVELOPE',
      `${where}.k is ${describe(k)}, which is none of the representations import version ${String(IMPORT_FORMAT_VERSION)} defines`,
    );
  }
  const derivedBy = raw['derivedBy'];
  if (!isTransformation(derivedBy)) {
    refused(
      'NOT_IMPORT_ENVELOPE',
      `${where}.derivedBy is ${describe(derivedBy)}, which is none of the transformations import version ${String(IMPORT_FORMAT_VERSION)} implements`,
    );
  }
  return {
    k,
    derivedBy,
    basis: requireDigest(raw, 'basis', where),
    bytes: requireText(raw, 'bytes', where),
    sha256: requireDigest(raw, 'sha256', where),
    byteCount: requireWhole(raw, 'byteCount', where, 'a byte count'),
  };
}

/**
 * An import envelope read out of whatever was handed over, refusing the shapes that cannot be read.
 *
 * The order carries the reading, the way the capture reader's order does. The version is decided first,
 * because nothing else can be named until a reader knows which rules the bytes are read under. Structure
 * comes next, then the byte checks, so a record whose original does not hash to what it states is caught
 * before anything tries to interpret those bytes.
 */
export function parseImportEnvelope(value: unknown): ImportEnvelope {
  const root = requireObject(value, 'import envelope');
  const version = requireImplementedVersion(root['v']);
  requireKnownMembers(root, ['v', 'provider', 'original', 'imported', 'derived'], 'import envelope');

  const provider = requireObject(root['provider'], 'provider');
  requireKnownMembers(provider, ['name', 'exportId'], 'provider');

  const original = requireObject(root['original'], 'original');
  requireKnownMembers(original, ['bytes', 'sha256', 'byteCount', 'signedByProvider'], 'original');

  const imported = requireObject(root['imported'], 'imported');
  requireKnownMembers(imported, ['at'], 'imported');

  const derived = root['derived'];
  if (!Array.isArray(derived) || derived.length === 0) {
    refused(
      'NOT_IMPORT_ENVELOPE',
      `derived is ${describe(derived)}, and an envelope states the representations the normalization produced`,
    );
  }
  const rows = derived.map((entry, index) => readDerived(entry, `derived[${String(index)}]`));
  const kinds = rows.map((row) => row.k);
  const twice = kinds.find((kind, at) => kinds.indexOf(kind) !== at);
  if (twice !== undefined) {
    refused(
      'NOT_IMPORT_ENVELOPE',
      `derived states '${twice}' twice, and one envelope holds one representation of one kind`,
    );
  }

  const envelope: ImportEnvelope = {
    v: version,
    provider: { name: requireText(provider, 'name', 'provider'), exportId: requireText(provider, 'exportId', 'provider') },
    original: {
      bytes: requireText(original, 'bytes', 'original'),
      sha256: requireDigest(original, 'sha256', 'original'),
      byteCount: requireWhole(original, 'byteCount', 'original', 'a byte count'),
      signedByProvider: requireBoolean(original, 'signedByProvider', 'original'),
    },
    imported: { at: requireWhole(imported, 'at', 'imported', 'a unix time') },
    derived: rows,
  };

  const originalBytes = decodeStated(envelope.original, 'original');
  const originalDigest = toHex(sha256(originalBytes));
  for (const [index, row] of envelope.derived.entries()) {
    decodeStated(row, `derived[${String(index)}]`);
    if (row.basis !== originalDigest) {
      refused(
        'EVIDENCE_DIGEST_MISMATCH',
        `derived[${String(index)}] names basis ${row.basis} and the original beside it hashes to ${originalDigest}`,
      );
    }
  }
  return envelope;
}

/** The transformations this version implements, by the name a derived representation cites. */
const TRANSFORMATIONS: Readonly<Record<ImportTransformation, (originalBytes: Uint8Array) => ImportNormalization>> = {
  normalizeProviderExport,
};

/**
 * Read an envelope, and say what can be concluded from it.
 *
 * Pure: it takes a document, runs the shipped normalization over the original the document holds, and
 * compares what the rules produce with what the record states. It writes nothing and fetches nothing.
 *
 * The two checks this adds to the layout are the reading's own. Each derived representation is re-derived:
 * the transformation its `derivedBy` names runs over the original's bytes again, and the digest the record
 * states for the representation has to be the digest that run produces, so a view somebody edited into
 * the envelope, or produced with another rule set, is refused rather than handed on beside a digest that
 * agrees with nobody's code. And the report is computed, not read: it is the shipped rules' reading of the
 * export, every time, which is what makes the same input yield the same sentences.
 */
export function readImportEnvelope(value: unknown): ImportReading {
  const envelope = parseImportEnvelope(value);
  const originalBytes = decodeStated(envelope.original, 'original');
  const runs = new Map<ImportTransformation, ImportNormalization>();
  for (const [index, row] of envelope.derived.entries()) {
    let run = runs.get(row.derivedBy);
    if (run === undefined) {
      run = TRANSFORMATIONS[row.derivedBy](originalBytes);
      runs.set(row.derivedBy, run);
    }
    const produced = toHex(sha256(run.bytes));
    if (produced !== row.sha256) {
      refused(
        'EVIDENCE_DIGEST_MISMATCH',
        `derived[${String(index)}] states sha256 ${row.sha256} and the rule '${row.derivedBy}' produces ${produced} from the original beside it`,
      );
    }
  }
  // The layout refuses an envelope with no derived representation, so one run of the loop above has
  // happened and the map holds at least one reading; the check states that invariant rather than
  // assuming it, and it is the branch a caller cannot reach with a document `parseImportEnvelope` took.
  const normalization: ImportNormalization | undefined = runs.values().next().value;
  if (normalization === undefined) {
    return refused('NOT_IMPORT_ENVELOPE', 'an envelope with no derived representation has no reading to hand back');
  }
  return {
    stated: {
      provider: envelope.provider,
      importedAt: envelope.imported.at,
      signedByProvider: envelope.original.signedByProvider,
      derived: envelope.derived,
    },
    repeated: {
      originalBytes,
      sha256: toHex(sha256(originalBytes)),
      normalizedSha256: toHex(sha256(normalization.bytes)),
    },
    report: normalization.report,
  };
}

/**
 * The record's identity, for whatever store an importer writes to.
 *
 * The digest is over the record's canonical JSON rather than over the values of its fields, following
 * `captureRecordKey`, because what has to be unique is the document a store holds and hands back. What it
 * is taken over is the record's content: the version, the provider it names and the original it holds.
 * `imported` dates the intake and `derived` follows from the original under the version's rules, so
 * neither enters the key, and a second intake of one export states its own instant, derives the same view
 * and writes no second record. The content is one export and the key says so; when the record was taken
 * in is a fact beside the record, not a second record.
 */
export function importEnvelopeKey(envelope: ImportEnvelope): string {
  const content = { v: envelope.v, provider: envelope.provider, original: envelope.original };
  return toHex(sha256(new TextEncoder().encode(`${IMPORT_KEY_DOMAIN}${canonicalJson(content)}`)));
}

// The prefix is a domain, not decoration: a key is a digest of a document, and one that an original's or
// a derived representation's digest could stand in for would let a reader confuse the three.
const IMPORT_KEY_DOMAIN = 'ashaveri/import-v1 ';

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      return refused('NOT_IMPORT_ENVELOPE', 'an import envelope holds a number no JSON document can state');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : 1));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`;
  }
  return refused('NOT_IMPORT_ENVELOPE', `an import envelope holds a ${typeof value}, which no store can key on`);
}
