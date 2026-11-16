import { ReceiptError } from './errors.js';
import { firstForgingCodePoint } from './line-text.js';
import { readJsonBytes, type JsonObject } from './json-text.js';
import { isMarkingScheme, type MarkingScheme } from './receipt.js';

/**
 * The disclosure record: a deployment's statement about the notice it owed beside a marked response.
 *
 * A receipt attests one response and the region its marking names, and neither of those two facts says who
 * owed a disclosure, which duty the notice answers, or what became of the mark when the content was copied,
 * rendered and exported. This record states those things beside the marking region rather than inside the
 * receipt: the payload's member set is frozen, and a record about disclosure is a different subject from the
 * attestation, read by a different reader. It carries no signature, as the retention manifest carries none:
 * its trust arrives from whoever hands it over beside the receipt it speaks of, and nothing in this module
 * can tell a sealed record from a copy. What the module does guarantee is the layout: a malformed record is
 * refused with a named code, and the limits every record states are the format's own sentence, verbatim, so
 * a record cannot widen its own claims by rewording them.
 *
 * The duty pointers are a closed registry of five provisions, and each is a pointer for counsel rather than
 * a conclusion: the record names the provision a notice is said to answer, and whether that duty applies to
 * a deployment, or was met by what it served, is a judgment this layout does not make. The scheme member is
 * read against the same marking registry `mk.sch` reads, so the record names the mark that exists rather
 * than inventing a second vocabulary, and a label outside that registry is refused by the one code the
 * registry owns.
 *
 * The transformation set is the record's account of what the mark survived: every entry names one
 * transformation of the content path and the outcome measured through it, and an unsupported transformation
 * is recorded as such rather than omitted, because a list of only the transformations that worked is a
 * claim about a path nobody tested whole. The reader cannot force the account to be honest, the same way no
 * reader of a retention manifest can force its figures to be true; what it refuses is a record that states
 * no outcome, states one outside the three the layout enumerates, or names one transformation twice.
 */

/** The versions this module reads, and the only place a disclosure record version is asked. */
export const DISCLOSURE_RECORD_VERSIONS: readonly number[] = [1];

/** The members of the one layout, in the order the writer emits them and the spec publishes them. */
export const DISCLOSURE_RECORD_V1_MEMBERS = ['v', 'obligor', 'duty', 'scheme', 'served', 'transformations', 'limits'] as const;

/**
 * The duty pointers the layout enumerates, each naming one provision a notice may answer. The citations
 * beside them are the instrument and provision as the estate's own sources name them; they are pointers
 * for counsel to weigh, not conclusions about applicability, and the record's limits sentence says so.
 */
export const DISCLOSURE_DUTY_POINTERS = [
  'ai-act-50-1',
  'ai-act-50-4',
  'ai-act-50-5',
  'difc-reg-10-2-2-b',
  'kr-enforcement-decree-23-2',
] as const;

export type DisclosureDutyPointer = (typeof DISCLOSURE_DUTY_POINTERS)[number];

/** The citation each pointer names, in the order the registry declares them. */
export const DISCLOSURE_DUTY_CITATIONS: Readonly<Record<DisclosureDutyPointer, string>> = {
  'ai-act-50-1': 'AI Act (Regulation (EU) 2024/1689), Article 50(1)',
  'ai-act-50-4': 'AI Act (Regulation (EU) 2024/1689), Article 50(4)',
  'ai-act-50-5': 'AI Act (Regulation (EU) 2024/1689), Article 50(5)',
  'difc-reg-10-2-2-b': 'DIFC Regulation 10.2.2(b)',
  'kr-enforcement-decree-23-2': 'Korea Enforcement Decree 23(2)',
};

/** The two things a record can state were served: the notice text, or the marked region named by digest. */
export const DISCLOSURE_SERVED_KINDS = ['text', 'region'] as const;
export const DISCLOSURE_SERVED_TEXT_MEMBERS = ['kind', 'text'] as const;
export const DISCLOSURE_SERVED_REGION_MEMBERS = ['kind', 'sha256'] as const;

/**
 * What one transformation did to the mark's detectability. `detectable` means the published extraction
 * rule still locates exactly one region after the transformation; `not-detectable` means it does not;
 * `untested` means the transformation is named and no run through it exists, which is the honest entry
 * for a transformation the content path has but the harness does not implement.
 */
export const DISCLOSURE_TRANSFORMATION_OUTCOMES = ['detectable', 'not-detectable', 'untested'] as const;

export type DisclosureTransformationOutcome = (typeof DISCLOSURE_TRANSFORMATION_OUTCOMES)[number];

export const DISCLOSURE_TRANSFORMATION_MEMBERS = ['name', 'outcome'] as const;

/**
 * The limits every record states, verbatim. The format owns this sentence rather than the writer: a
 * record whose limits member says anything else is refused, because the one thing a reader of a
 * disclosure record must not have to weigh is whether the record's own account of its limits is true.
 * A JSON transcript region is not a pixel or audio watermark, and a reader holding only the words of a
 * completion has no region to look for; both facts are stated here so every record and every detection
 * answer carries them in one spelling.
 */
export const DISCLOSURE_RECORD_LIMITS =
  'This record describes a marking in a JSON transcript region, not a pixel or audio watermark. ' +
  'A reader holding only the text of a completion, copied or retyped out of the transcript, has no region ' +
  'to look for and cannot prove the mark from those words. The duty pointers name provisions for counsel ' +
  'to weigh, not conclusions that a duty applies or was met.';

/**
 * The width one text member of this layout may hold, in UTF-16 units of the text as this package holds
 * it. The notice text is the longest thing a record states, and a ceiling keeps a refusal readable and a
 * printed row bounded; the limits sentence sits under it by construction.
 */
export const DISCLOSURE_TEXT_MAX_UNITS = 400;

/** The notice text served to a reader, in the deployment's own words. */
export interface DisclosureServedText {
  readonly kind: 'text';
  readonly text: string;
}

/** The marked region served, named by the digest `mk.d` carries: sha256 of the region's exact bytes. */
export interface DisclosureServedRegion {
  readonly kind: 'region';
  readonly sha256: string;
}

export type DisclosureServed = DisclosureServedText | DisclosureServedRegion;

/** One transformation of the content path, and what the mark's detectability did through it. */
export interface DisclosureTransformation {
  readonly name: string;
  readonly outcome: DisclosureTransformationOutcome;
}

/** A disclosure record at version 1: the whole layout, every member required. */
export interface DisclosureRecord {
  readonly v: 1;
  /** Who owed the notice, named as the deployment names itself. */
  readonly obligor: string;
  readonly duty: DisclosureDutyPointer;
  readonly scheme: MarkingScheme;
  readonly served: DisclosureServed;
  readonly transformations: readonly DisclosureTransformation[];
  /** The format's limits sentence, verbatim; the reader refuses any other text at this position. */
  readonly limits: string;
}

const text = new TextEncoder();

function bad(detail: string): ReceiptError {
  return new ReceiptError('DISCLOSURE_RECORD_BAD_DOCUMENT', detail);
}

function readMap(value: unknown, position: string): JsonObject {
  if (!(value instanceof Map)) throw bad(`${position} is not an object`);
  return value as JsonObject;
}

/**
 * One text member as this layout reads it: non-empty, no wider than the ceiling, no pad on either side,
 * and no character that would end, hide or reorder the printed row it belongs to. The class is the one
 * `line-text.ts` owns, taken through its own helper rather than spelled again here.
 */
function requireText(value: unknown, position: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw bad(`${position} must be a non-empty text`);
  }
  if (value.length > DISCLOSURE_TEXT_MAX_UNITS) {
    throw bad(`${position} is wider than the ${String(DISCLOSURE_TEXT_MAX_UNITS)} units this layout holds`);
  }
  if (value.trim() !== value) {
    throw bad(`${position} carries leading or trailing space, which a printed row does not carry`);
  }
  const forging = firstForgingCodePoint(value);
  if (forging !== undefined) {
    throw bad(`${position} carries the character U+${forging.toString(16).toUpperCase().padStart(4, '0')}, which forges the line it is printed on`);
  }
  return value;
}

/** A digest, stated the way this estate states every one of them: sixty-four lowercase hex characters. */
function requireDigest(value: unknown, position: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw bad(`${position} must be sixty-four lowercase hex characters`);
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

/**
 * A disclosure record, out of the bytes of the file as it sits on the volume.
 *
 * The reading is the strict one the retention manifest uses, through the same JSON scanner and for the
 * same two reasons: a member named twice would be settled by `JSON.parse` into whichever value the parser
 * reached last while the bytes carry both, and a float wearing an integer arrives at a check as the very
 * number it imitates. The version is asked of `DISCLOSURE_RECORD_VERSIONS` before any member is read,
 * because which member list applies is the one question a wrong version cannot be talked out of.
 */
export function parseDisclosureRecord(bytes: Uint8Array): DisclosureRecord {
  const raw = readJsonBytes(bytes, (detail) => {
    throw new ReceiptError('DISCLOSURE_RECORD_BAD_DOCUMENT', detail);
  });
  const document = readMap(raw, 'record');
  const version = document.get('v');
  if (typeof version !== 'number') {
    throw bad('v must be an integer disclosure record version');
  }
  if (!DISCLOSURE_RECORD_VERSIONS.includes(version)) {
    throw new ReceiptError(
      'DISCLOSURE_RECORD_UNSUPPORTED_VERSION',
      `disclosure record version ${String(version)} is not a layout this package reads`,
    );
  }
  assertDefined(document, DISCLOSURE_RECORD_V1_MEMBERS, 'record');
  const scheme = document.get('scheme');
  if (typeof scheme !== 'string') throw bad('scheme must be a text marking scheme label');
  if (!isMarkingScheme(scheme)) {
    throw new ReceiptError(
      'UNSUPPORTED_SCHEME',
      `the disclosure record's scheme member names '${scheme}', outside the marking registry this package reads`,
    );
  }
  const duty = document.get('duty');
  if (duty === undefined) throw bad('duty is required: a record states which provision its notice answers');
  if (typeof duty !== 'string') throw bad('duty must be a text duty pointer label');
  if (!(DISCLOSURE_DUTY_POINTERS as readonly string[]).includes(duty)) {
    throw new ReceiptError(
      'DISCLOSURE_RECORD_UNKNOWN_DUTY',
      `duty names ${JSON.stringify(duty)}, outside the pointers the layout enumerates`,
    );
  }
  const served = readServed(document.get('served'), scheme);
  const transformations = readTransformations(document.get('transformations'));
  const limits = document.get('limits');
  if (limits !== DISCLOSURE_RECORD_LIMITS) {
    throw bad('limits must state the limits sentence this format owns, verbatim; a record does not word its own limits');
  }
  return {
    v: 1,
    obligor: requireText(document.get('obligor'), 'obligor'),
    duty: duty as DisclosureDutyPointer,
    scheme,
    served,
    transformations,
    limits,
  };
}

/** The served member, whose arm the kind label decides, and the cross-rule the scheme states beside it. */
function readServed(value: unknown, scheme: MarkingScheme): DisclosureServed {
  const raw = readMap(value, 'served');
  const kind = raw.get('kind');
  if (kind === 'text') {
    assertDefined(raw, DISCLOSURE_SERVED_TEXT_MEMBERS, 'served');
    return { kind: 'text', text: requireText(raw.get('text'), 'served.text') };
  }
  if (kind === 'region') {
    assertDefined(raw, DISCLOSURE_SERVED_REGION_MEMBERS, 'served');
    if (scheme === 'none') {
      throw bad('served names a region beside a scheme that declares no region of the response is marked, which is the record contradicting itself');
    }
    return { kind: 'region', sha256: requireDigest(raw.get('sha256'), 'served.sha256') };
  }
  throw bad(`served.kind names ${JSON.stringify(String(kind))}, outside the two things a record states were served`);
}

/** The transformation set: non-empty, one outcome per named transformation, and no name stated twice. */
function readTransformations(value: unknown): readonly DisclosureTransformation[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw bad('transformations must be a non-empty array: a record states what it tested, and an empty list states nothing');
  }
  const named = new Set<string>();
  return value.map((one, index): DisclosureTransformation => {
    const site = `transformations[${String(index)}]`;
    const raw = readMap(one, site);
    assertDefined(raw, DISCLOSURE_TRANSFORMATION_MEMBERS, site);
    const name = requireText(raw.get('name'), `${site}.name`);
    const outcome = raw.get('outcome');
    if (typeof outcome !== 'string' || !(DISCLOSURE_TRANSFORMATION_OUTCOMES as readonly string[]).includes(outcome)) {
      throw bad(`${site}.outcome names ${JSON.stringify(String(outcome))}, outside the three outcomes the layout enumerates`);
    }
    if (named.has(name)) {
      throw bad(`transformations names ${JSON.stringify(name)} twice, so one transformation is stated twice and its two outcomes cannot both be read`);
    }
    named.add(name);
    return { name, outcome: outcome as DisclosureTransformationOutcome };
  });
}

/**
 * The record as a file: two-space indented, newline terminated, in the member order the layout declares.
 * The bytes are what a reader hashes beside the receipt the record speaks of, so one record state has to
 * produce one byte string, and a writer that emitted the caller's key order would give two writers of one
 * state two digests.
 */
export function encodeDisclosureRecord(record: DisclosureRecord): Uint8Array {
  const served =
    record.served.kind === 'text'
      ? { kind: record.served.kind, text: record.served.text }
      : { kind: record.served.kind, sha256: record.served.sha256 };
  const document: Record<string, unknown> = {
    v: record.v,
    obligor: record.obligor,
    duty: record.duty,
    scheme: record.scheme,
    served,
    transformations: record.transformations.map((one) => ({ name: one.name, outcome: one.outcome })),
    limits: record.limits,
  };
  return text.encode(`${JSON.stringify(document, null, 2)}\n`);
}

/**
 * The bytes this writer would produce for a record, run back through this module's own reader before a
 * caller files them beside a receipt. A deployment cannot hand over a record its own reader refuses, which
 * is the same promise `retentionDocumentBytes` makes about a manifest: the refusal arrives where the bytes
 * are made rather than at a reviewer holding them later.
 */
export function disclosureRecordBytes(record: DisclosureRecord): Uint8Array {
  const bytes = encodeDisclosureRecord(record);
  parseDisclosureRecord(bytes);
  return bytes;
}