import { SdkError } from './errors.js';

/**
 * The import normalization: the named rules that read a provider export, the one document they fold it
 * into, and the report of what they could not read.
 *
 * An import envelope holds a provider export's exact bytes. This module is the reading those bytes get:
 * one named function per estate field the export feeds, folded by `normalizeProviderExport` into the
 * normalized document that a derived representation carries, beside the report of every position the
 * export states that no rule reads and every position a rule reads that the export states nothing at.
 *
 * The provider's document is not ours, so its extra fields are not refused. A provider that carries a
 * field this rule set does not read is a provider whose export is larger than this reading, and refusing
 * it would turn every future field of every provider into an unimportable document while teaching nobody
 * what the field was. The honest answer is the one this module gives: the original bytes stay held whole,
 * the normalized document states what the rules read, and the report names every position left over with
 * the same sentence every time, because the same input runs the same named functions over the same
 * sorted field list and nothing here reads a clock, a locale or a filesystem.
 *
 * A value of the wrong shape at a position a rule reads is the other answer, and it is a refusal. The
 * field is one this reading knows and its value is one no rule reads, so the normalized document would
 * have to omit a field the export did state, which is the silence the report exists to prevent and one
 * the report cannot repair: the position is read, and what it states is not a value. The refusal names
 * the position and the shape the rule reads there, and its sentence is as fixed as the report's.
 *
 * Nothing here holds a credential, reaches a network or names a provider's product. The field names below
 * are the synthetic provider's vocabulary, the one the published vectors build their export from, and a
 * real provider's export reaches these rules through the adapter this package does not ship.
 */

/** The version of the normalized document a derived representation carries, the number in its `v`. */
export const NORMALIZED_EXPORT_VERSION = 1;

/**
 * The names of the five rules this version runs, in the order the estate fields are read.
 *
 * A report row cites the rule that found its position, so a name here is a published identifier and not a
 * comment: `docs/import-v1.md` states which rule reads which field, and `import-normalize.test.ts` walks
 * this list against the table below so a rule added to one and not the other stops the run.
 */
export const NORMALIZATION_RULE_NAMES = [
  'normalizeProvider',
  'normalizeExportId',
  'normalizeIssuedAt',
  'normalizeModel',
  'normalizeCompletions',
] as const;

/** One of the five names above. */
export type NormalizationRuleName = (typeof NORMALIZATION_RULE_NAMES)[number];

/** The name of the transformation a derived representation cites, which runs every rule below. */
export const IMPORT_TRANSFORMATION = 'normalizeProviderExport';

/** The parsed provider export: a JSON object, read as members rather than as an object this module shapes. */
export type ExportMembers = Record<string, unknown>;

/** One normalized completion entry: the estate's spelling of one entry of the provider's `completions`. */
export interface NormalizedExportItem {
  /** The provider's own name for the entry, read off `ref`. */
  readonly id: string;
  /** The digest of the entry's original bytes, read off `sha256`. */
  readonly sha256: string;
  /** The instant the entry was stated at, in whole unix seconds, read off `at`. */
  readonly at: number;
}

/** One row of the report: a position no rule reads, or a position a rule reads that the export states nothing at. */
export interface ImportReportRow {
  /** Which of the two outcomes this row states. The two never merge: one is the provider's silence and one is our reach. */
  readonly kind: 'unsupported-field' | 'missing-field';
  /** The position, as the export spells it: a top-level member name, or `completions[i]` and one member of it. */
  readonly field: string;
  /** One line, the same for the same input: what the position states and which rule or rule set it met. */
  readonly states: string;
}

/** What the normalized document is, and what the reading could not take from the export. */
export interface ImportNormalization {
  /** The normalized document's exact bytes: UTF-8 JSON, its members in the order the rule table states them. */
  readonly bytes: Uint8Array;
  /** The report, one row per position, sorted by position so one export carries one report however it is spelled. */
  readonly report: readonly ImportReportRow[];
}

/** What one rule made of the export: the normalized value and the rows the rule found beside it, or nothing. */
export interface RuleReading {
  readonly value: string | number | readonly NormalizedExportItem[];
  readonly rows: readonly ImportReportRow[];
}

/** One rule of this version: the export member it reads, the normalized member it writes, and the function that reads it. */
export interface NormalizationRule {
  /** The top-level member of the export this rule reads. A member of the export outside these is reported. */
  readonly field: string;
  /** The member of the normalized document this rule writes, which is the export field's second spelling. */
  readonly member: string;
  /** The rule's own name, cited in the report row it leads to. */
  readonly name: NormalizationRuleName;
  readonly read: (exported: ExportMembers) => RuleReading | null;
}

const HEX64 = /^[0-9a-f]{64}$/;

function refused(message: string): never {
  throw new SdkError('NOT_IMPORT_ENVELOPE', message);
}

function describe(value: unknown): string {
  if (typeof value === 'string') return `'${value}'`;
  if (value === undefined) return 'absent';
  if (value === null) return 'null';
  return `a ${Array.isArray(value) ? 'list' : typeof value}`;
}

/** A name a rule reads, which is a non-empty string or nothing. A value of another shape is refused at its position. */
function readText(exported: ExportMembers, field: string, rule: string, what: string): string | null {
  const value = exported[field];
  if (value === undefined) return null;
  if (typeof value !== 'string' || value.length === 0) {
    refused(`the export states ${describe(value)} at '${field}', where normalization rule '${rule}' reads ${what}`);
  }
  return value;
}

/** A whole non-negative instant a rule reads, which is a safe-integer count of unix seconds or nothing. */
function readInstant(exported: ExportMembers, field: string, rule: string): number | null {
  const value = exported[field];
  if (value === undefined) return null;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    refused(
      `the export states ${describe(value)} at '${field}', where normalization rule '${rule}' reads a whole number of unix seconds`,
    );
  }
  return value;
}

/**
 * The provider's name for itself, read off `provider`.
 *
 * The claim is the envelope's and the value is the export's: this rule copies the name the export states
 * and reads nothing out of its content, which is the same reading the estate gives every other name a
 * document states for itself.
 */
export function normalizeProvider(exported: ExportMembers): string | null {
  return readText(exported, 'provider', 'normalizeProvider', 'the name of the system that served the export');
}

/** The provider's own name for this export, read off `export_id`. */
export function normalizeExportId(exported: ExportMembers): string | null {
  return readText(exported, 'export_id', 'normalizeExportId', "the provider's own name for the export");
}

/** The instant the provider states the export carries, read off `issued`. */
export function normalizeIssuedAt(exported: ExportMembers): number | null {
  return readInstant(exported, 'issued', 'normalizeIssuedAt');
}

/** The model the export speaks about, read off `model`. */
export function normalizeModel(exported: ExportMembers): string | null {
  return readText(exported, 'model', 'normalizeModel', 'the name of the model the export speaks about');
}

/** The members `normalizeCompletions` reads from each entry of the provider's `completions`, in normalized order. */
const EXPORT_ITEM_MEMBERS = ['ref', 'sha256', 'at'] as const;

/** What one pass over the provider's `completions` yielded: the entries it could state and the rows it found. */
interface CompletionsReading {
  readonly items: readonly NormalizedExportItem[];
  readonly rows: readonly ImportReportRow[];
}

/**
 * The completion entries, read off `completions`.
 *
 * Each entry is read member by member, and the reading has two halves that arrive together or not at all:
 * an entry all of whose three members are readable reaches the normalized document, and an entry with a
 * member missing reaches the report only. An entry is not carried half-stated, because the normalized
 * document's entry shape is fixed and an entry with no digest or no instant is not an entry this estate
 * can place; the report names every member it could not read, so the entry that fell out is accounted
 * for member by member and the omission is never silent.
 *
 * An entry member outside the three is reported as a position no rule reads, beside the entry it sits in.
 * That is the top level's own rule stated at a second site, and it is stated there on purpose: a member a
 * provider adds inside one entry is a position this reading does not have, and naming it at the entry
 * says where it is rather than counting the array as one unread field.
 */
function readCompletions(exported: ExportMembers): CompletionsReading | null {
  const value = exported['completions'];
  if (value === undefined) return null;
  if (!Array.isArray(value)) {
    refused(
      `the export states ${describe(value)} at 'completions', where normalization rule 'normalizeCompletions' reads a list of completion entries`,
    );
  }
  const items: NormalizedExportItem[] = [];
  const rows: ImportReportRow[] = [];
  for (const [index, entry] of value.entries()) {
    const where = `completions[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      refused(
        `the export states ${describe(entry)} at '${where}', where normalization rule 'normalizeCompletions' reads one entry object`,
      );
    }
    const members = entry as ExportMembers;
    for (const member of Object.keys(members).sort()) {
      if (!(EXPORT_ITEM_MEMBERS as readonly string[]).includes(member)) {
        const field = `${where}.${member}`;
        rows.push({ kind: 'unsupported-field', field, states: unsupportedSentence(field) });
      }
    }
    const id = readItemText(members, where, 'ref', 'a name');
    const sha256 = readItemText(members, where, 'sha256', 'a sha256 digest, sixty-four lowercase hex characters');
    const at = readItemInstant(members, where, 'at');
    for (const [member, readable] of [
      ['ref', id],
      ['sha256', sha256],
      ['at', at],
    ] as const) {
      if (readable === null && members[member] === undefined) {
        const field = `${where}.${member}`;
        rows.push({ kind: 'missing-field', field, states: missingSentence(field, 'normalizeCompletions') });
      }
    }
    if (id !== null && sha256 !== null && at !== null) items.push({ id, sha256, at });
  }
  return { items, rows };
}

/**
 * The completion entries as the normalized document states them, which is the reading above with its
 * report rows left to the driver.
 */
export function normalizeCompletions(exported: ExportMembers): readonly NormalizedExportItem[] | null {
  return readCompletions(exported)?.items ?? null;
}

/** One entry member that is a name or a digest, or nothing. A value of another shape is refused at its position. */
function readItemText(members: ExportMembers, where: string, field: string, what: string): string | null {
  const value = members[field];
  if (value === undefined) return null;
  if (typeof value !== 'string' || value.length === 0 || (field === 'sha256' && !HEX64.test(value))) {
    refused(
      `the export states ${describe(value)} at '${where}.${field}', where normalization rule 'normalizeCompletions' reads ${what}`,
    );
  }
  return value;
}

/** One entry member that is an instant, or nothing. A value of another shape is refused at its position. */
function readItemInstant(members: ExportMembers, where: string, field: string): number | null {
  const value = members[field];
  if (value === undefined) return null;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    refused(
      `the export states ${describe(value)} at '${where}.${field}', where normalization rule 'normalizeCompletions' reads a whole number of unix seconds`,
    );
  }
  return value;
}

/** One rule whose readings carry no rows of their own, which is every rule but the completions one. */
function withoutRows(read: (exported: ExportMembers) => string | number | null): (exported: ExportMembers) => RuleReading | null {
  return (exported) => {
    const value = read(exported);
    return value === null ? null : { value, rows: [] };
  };
}

/**
 * The rules this version runs, in the order the normalized document states their members.
 *
 * The table is what `normalizeProviderExport` walks to decide which top-level members of an export are
 * read at all, so an export member absent from the `field` column is reported rather than dropped. The
 * two spellings of every field stand in one row on purpose: a field added to one column and not the
 * other is the disagreement that `import-normalize.test.ts` refuses, and it is the shape of defect a
 * reader of this table would otherwise have to reconstruct from the normalized document's bytes.
 */
export const NORMALIZATION_RULES: readonly NormalizationRule[] = [
  { field: 'provider', member: 'provider', name: 'normalizeProvider', read: withoutRows(normalizeProvider) },
  { field: 'export_id', member: 'exportId', name: 'normalizeExportId', read: withoutRows(normalizeExportId) },
  { field: 'issued', member: 'issuedAt', name: 'normalizeIssuedAt', read: withoutRows(normalizeIssuedAt) },
  { field: 'model', member: 'model', name: 'normalizeModel', read: withoutRows(normalizeModel) },
  {
    field: 'completions',
    member: 'items',
    name: 'normalizeCompletions',
    read: (exported) => {
      const reading = readCompletions(exported);
      return reading === null ? null : { value: reading.items, rows: reading.rows };
    },
  },
];

/** Every top-level member this version reads, which is also the set an export member is weighed against. */
const READ_FIELDS: readonly string[] = NORMALIZATION_RULES.map((rule) => rule.field);

/** The sentence an unsupported row carries: one spelling for the same input, whichever run meets it. */
function unsupportedSentence(field: string): string {
  return `the export carries '${field}', which no normalization rule of import version ${String(NORMALIZED_EXPORT_VERSION)} reads`;
}

/** The sentence a missing row carries. The rule is named, so the row says whose reading found nothing. */
function missingSentence(field: string, rule: string): string {
  return `the export carries nothing at '${field}', which normalization rule '${rule}' reads`;
}

/**
 * The normalized document and the report, out of a provider export's exact bytes.
 *
 * The driver is the one entry point of this module, and its order is the reading. The bytes decode as
 * UTF-8 and parse as one JSON object first, because a document that is not one object has no members to
 * weigh; then the top-level members sort and split into read and unread; then each rule runs, in the order
 * the table states, so the normalized document's members are written in one order for one input; last the
 * report rows sort by position.
 *
 * The sort is what makes the report a function of the input. The export's own member order is not read:
 * two spellings of one export that differ only in the order of their members are one import of one export,
 * and a report that kept the file's order would hand two sentences to two readers of one document.
 */
export function normalizeProviderExport(originalBytes: Uint8Array): ImportNormalization {
  const exported = decodeExport(originalBytes);
  const rows: ImportReportRow[] = [];
  for (const member of Object.keys(exported).sort()) {
    if (!READ_FIELDS.includes(member)) {
      rows.push({ kind: 'unsupported-field', field: member, states: unsupportedSentence(member) });
    }
  }
  const normalized: Record<string, unknown> = { v: NORMALIZED_EXPORT_VERSION };
  for (const rule of NORMALIZATION_RULES) {
    const outcome = rule.read(exported);
    if (outcome === null) {
      rows.push({ kind: 'missing-field', field: rule.field, states: missingSentence(rule.field, rule.name) });
      continue;
    }
    rows.push(...outcome.rows);
    normalized[rule.member] = outcome.value;
  }
  rows.sort((one, other) => (one.field < other.field ? -1 : one.field > other.field ? 1 : 0));
  return { bytes: new TextEncoder().encode(JSON.stringify(normalized)), report: rows };
}

/**
 * The export's bytes as one JSON object.
 *
 * The decode is the reading's first step and its failure modes are kept apart in words while sharing one
 * code: bytes that are not UTF-8 at all are not text this reading can open, and text that is not one JSON
 * object is text this reading has no members to weigh. Both are refusals, because a normalized document
 * cannot be produced from nothing and an import that stated one anyway would be stating a document this
 * reading never reached.
 */
function decodeExport(originalBytes: Uint8Array): ExportMembers {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(originalBytes);
  } catch {
    return refused(
      "the export's bytes are not UTF-8 text, and normalization rule 'normalizeProviderExport' reads the export as JSON",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (err) {
    return refused(
      `the export's bytes do not parse as one JSON document (${err instanceof Error ? err.message : String(err)}), and normalization rule 'normalizeProviderExport' reads one`,
    );
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return refused(
      `the export decodes to ${describe(parsed)}, where normalization rule 'normalizeProviderExport' reads one JSON object of members`,
    );
  }
  return parsed as ExportMembers;
}
