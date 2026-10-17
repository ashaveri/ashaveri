import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { ReceiptError } from '@ashaveri/receipt';
import {
  SdkError,
  fromBase64Url,
  importEnvelopeKey,
  normalizeProviderExport,
  parseImportEnvelope,
  readImportEnvelope,
  toBase64Url,
  toHex,
  type ImportReportRow,
} from '@ashaveri/sdk';
import { labeled } from './seed.ts';
import { FIXED_IAT } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');
const EXPORTS = join(DATA, 'exports');

/**
 * The import envelope vectors: whole envelopes, the answer the published reader gives each one, and the
 * key a store takes it under.
 *
 * The synthetic provider export these vectors hold is built here and committed beside them as
 * `data/exports/provider-export-v1.json`. It is a fixture and it says so: no real provider's bytes, no
 * provider's name, no credential and no network call reach this file. `main` writes the export, then stops
 * unless the envelope's original is that file byte for byte, unless the committed export carries no
 * position the shipped rules do not read, and unless every row answers the direction its case states.
 *
 * What is published is bytes, readings and keys. How an adapter came to hold an export, what it retried
 * and what it authenticated with reaches no row here; that half of the unit is Confidential and out of
 * this package.
 *
 * The derived representation every accepted envelope carries is `normalizeProviderExport` output, so a row
 * stands on the same transformation `readImportEnvelope` re-runs when the suite replays it, and the two
 * readings a row publishes are the shipped reader's own: `originalSha256` over the bytes it hands back and
 * `normalizedSha256` over what the rules produce from them.
 */

const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);
const digestHex = (bytes: Uint8Array): string => toHex(sha256(bytes));

/** The synthetic provider, its name for this export, and the instants every row is dated by. */
const PROVIDER = 'fixture-provider';
const EXPORT_ID = 'EXP-2026-10-01-0001';
const ISSUED_AT = FIXED_IAT + 30;
const IMPORTED_AT = FIXED_IAT + 60;

/** One entry of the export's `completions`, its digest derived from a label rather than drawn. */
function entry(ref: string, label: string, at: number): Record<string, unknown> {
  return { ref, sha256: digestHex(labeled(label)), at };
}

/** The synthetic provider's export: every member the five rules read, two whole entries, nothing else. */
function baseExport(): Record<string, unknown> {
  return {
    provider: PROVIDER,
    export_id: EXPORT_ID,
    issued: ISSUED_AT,
    model: 'fixture-model-1',
    completions: [
      entry('c-0001', 'ashaveri-fixtures/import/entry-1/v1', FIXED_IAT + 1),
      entry('c-0002', 'ashaveri-fixtures/import/entry-2/v1', FIXED_IAT + 9),
    ],
  };
}

/**
 * The export's bytes, exactly as the committed file holds them.
 *
 * One trailing newline belongs to the bytes on purpose: a text file that ends at its last brace has a
 * length divisible by three and a base64url spelling with no free tail bit, which would leave the refusal
 * row that states a second spelling of one export's bytes with no second spelling to state. The newline
 * is inside the original, so it is inside the digest, which is the point.
 */
const exportBytes = (exported: Record<string, unknown>): Uint8Array => TEXT(`${JSON.stringify(exported)}\n`);

/**
 * The envelope one export imports as, at one intake instant.
 *
 * The derived row is the shipped normalization's output over these bytes, so the record this suite
 * publishes is one the shipped code could have written, and `main` holds the original to the committed
 * export file.
 */
function envelopeFor(exported: Record<string, unknown>, importedAt: number): Record<string, unknown> {
  const bytes = exportBytes(exported);
  const derived = normalizeProviderExport(bytes).bytes;
  return {
    v: 1,
    provider: { name: PROVIDER, exportId: EXPORT_ID },
    original: {
      bytes: toBase64Url(bytes),
      sha256: digestHex(bytes),
      byteCount: bytes.length,
      signedByProvider: false,
    },
    imported: { at: importedAt },
    derived: [
      {
        k: 'normalized-export',
        derivedBy: 'normalizeProviderExport',
        basis: digestHex(bytes),
        bytes: toBase64Url(derived),
        sha256: digestHex(derived),
        byteCount: derived.length,
      },
    ],
  };
}

const HONEST = baseExport();
const HONEST_ENVELOPE = envelopeFor(HONEST, IMPORTED_AT);

type Block = Record<string, unknown>;
const originalOf = (envelope: Block): Block => envelope['original'] as Block;
const derivedOf = (envelope: Block): readonly Block[] => envelope['derived'] as readonly Block[];

/** One member of the envelope's original block replaced. */
function originalWith(envelope: Block, over: Block): Block {
  return { ...envelope, original: { ...originalOf(envelope), ...over } };
}

/** One member of the envelope's single derived row replaced. */
function derivedWith(envelope: Block, over: Block): Block {
  return { ...envelope, derived: [{ ...derivedOf(envelope)[0]!, ...over }] };
}

/** The same export object with members left out, which is how the export states nothing at a position. */
function without(exported: Block, ...members: readonly string[]): Block {
  const out = { ...exported };
  for (const member of members) delete out[member];
  return out;
}

/**
 * Another base64url spelling of the same bytes, by moving a tail bit no part of the document occupies.
 * It refuses to answer unless the move decodes back to the same bytes, so a row built on it states the
 * one fault it names rather than a byte string that decodes to something else.
 */
function secondSpelling(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const canonical = toBase64Url(bytes);
  const last = canonical[canonical.length - 1]!;
  const spelled = `${canonical.slice(0, -1)}${alphabet[alphabet.indexOf(last) + 1]!}`;
  if (toBase64Url(fromBase64Url(spelled)) !== canonical) {
    throw new Error(`${spelled} is not a second spelling of these ${String(bytes.length)} bytes`);
  }
  return spelled;
}

/** What a shipped step answered: its code and its sentence, or `ok` where it answered by handing something back. */
function answeredBy(run: () => unknown): { readonly outcome: string; readonly message: string } {
  try {
    run();
    return { outcome: 'ok', message: '' };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { outcome: err.code, message: err.message };
    throw new Error(`the shipped reader answered with something no registry declares: ${String(err)}`);
  }
}

/** What the published reader states about one accepted envelope, beside the key. */
function readingOf(envelope: Block): Block {
  const reading = readImportEnvelope(envelope);
  return {
    report: reading.report,
    originalSha256: reading.repeated.sha256,
    normalizedSha256: reading.repeated.normalizedSha256,
    derived: reading.stated.derived,
  };
}

interface Accepted {
  readonly name: string;
  readonly note: string;
  readonly envelope: Block;
  /** The name of the row this envelope is the second intake of, for the twice-import proof. */
  readonly againOf?: string;
  /** What this envelope's original changes about the committed export, where it changes anything. */
  readonly exportEdit?: string;
}

const EDITED_UNSUPPORTED: Block = { ...HONEST, region: 'eu-west-1' };
const EDITED_MISSING: Block = without(HONEST, 'model');
const EDITED_NESTED: Block = {
  ...without(HONEST, 'model'),
  completions: [
    { ...(HONEST['completions'] as readonly Block[])[0]!, cost_micros: 42 },
    without((HONEST['completions'] as readonly Block[])[1]!, 'sha256'),
  ],
};

const ACCEPTED: readonly Accepted[] = [
  {
    name: 'honest-export-imported',
    note: 'The export `data/exports/provider-export-v1.json` publishes, imported once: every position the five rules read is stated, the report is empty, and the derived row is the shipped normalization\u2019s output over exactly these bytes. The stored bytes are handed back unchanged, which is the half of this record the vectors exist to hold.',
    envelope: HONEST_ENVELOPE,
  },
  {
    name: 'honest-export-imported-again',
    note: 'The same export imported a second time, one day after the first intake. One block differs and it is the block the key excludes, so this record keys exactly as the first one: two intakes of one export are one record, not two. The derivation and the report are the same because the bytes are.',
    envelope: envelopeFor(HONEST, IMPORTED_AT + 86_400),
    againOf: 'honest-export-imported',
  },
  {
    name: 'unsupported-field-export',
    note: "The export with one member added that no rule reads, `region`. The envelope is still written and still read: the original holds the provider's bytes whole, the normalized document states what the rules read, and the report carries one `unsupported-field` row naming the position. Refusing the import would turn every future field of every provider into an unimportable document while teaching nobody what the field was.",
    envelope: envelopeFor(EDITED_UNSUPPORTED, IMPORTED_AT),
    exportEdit: "the committed export with `region` added",
  },
  {
    name: 'missing-field-export',
    note: "The export with its `model` member taken out. The reading survives it: the normalized document states no model, and the report carries one `missing-field` row naming the position and the rule that reads it. This row and the one above are the pair the two kinds are told apart by: one is the provider's silence and one is our reach, and neither sentence is the other.",
    envelope: envelopeFor(EDITED_MISSING, IMPORTED_AT),
    exportEdit: 'the committed export without `model`',
  },
  {
    name: 'nested-field-report',
    note: "The export with one member added inside an entry, one member taken out of another, and the `model` member absent as well: one `unsupported-field` row for `completions[0].cost_micros`, one `missing-field` row for `completions[1].sha256`, and one `missing-field` row for `model`, sorted by position rather than by arrival. The entry missing its digest falls out of the normalized `items` whole and is accounted for by the row, so the omission is never silent.",
    envelope: envelopeFor(EDITED_NESTED, IMPORTED_AT),
    exportEdit: 'the committed export with an entry member added, an entry member removed and `model` absent',
  },
];

interface Refusal {
  readonly name: string;
  readonly note: string;
  readonly envelope: Block;
  readonly stage: 'layout' | 'reading';
  readonly code: string;
}

/** The envelope of an export whose `issued` is a string: a value of no shape the rule there reads. */
const UNREADABLE_ENVELOPE: Block = (() => {
  const bad = TEXT(JSON.stringify({ ...HONEST, issued: 'yesterday' }));
  return derivedWith(
    originalWith(envelopeFor(HONEST, IMPORTED_AT), {
      bytes: toBase64Url(bad),
      sha256: digestHex(bad),
      byteCount: bad.length,
    }),
    { basis: digestHex(bad) },
  );
})();

/** The self-consistent bytes of a derived row that is not what the named rule produces. */
const OTHER_DERIVED: Uint8Array = TEXT('{"v":1}');

const REFUSALS: readonly Refusal[] = [
  {
    name: 'version-two',
    note: 'An envelope naming import format version 2. The version decides which members exist, so a reader with no rules for it refuses before one member is read, under the same code the capture reader answers the same question with.',
    envelope: { ...HONEST_ENVELOPE, v: 2 },
    stage: 'layout',
    code: 'UNSUPPORTED_VERSION',
  },
  {
    name: 'member-import-version-one-does-not-define',
    note: 'An envelope carrying `retainedAt`, a member no version of this layout defines. Closure holds here as it holds at every record of this estate: a writer that stated a field no reader knows was answering a question this record cannot ask, and dropping it quietly turns that answer into a silence.',
    envelope: { ...HONEST_ENVELOPE, retainedAt: IMPORTED_AT },
    stage: 'layout',
    code: 'NOT_IMPORT_ENVELOPE',
  },
  {
    name: 'derived-kind-no-version-defines',
    note: 'A derived row whose `k` names a representation this version does not define. A new reading of a provider export arrives as a new representation kind and a new version rather than as a word a reader falls through to its default handling on.',
    envelope: derivedWith(HONEST_ENVELOPE, { k: 'canonical-export' }),
    stage: 'layout',
    code: 'NOT_IMPORT_ENVELOPE',
  },
  {
    name: 'derived-transformation-no-version-implements',
    note: 'A derived row whose `derivedBy` names a transformation this version does not implement. The name a row cites is what a reader re-runs, so a name outside the shipped set is refused rather than handed on as a digest nobody can reproduce.',
    envelope: derivedWith(HONEST_ENVELOPE, { derivedBy: 'normalizeProviderCatalog' }),
    stage: 'layout',
    code: 'NOT_IMPORT_ENVELOPE',
  },
  {
    name: 'original-digest-of-another-document',
    note: 'The honest bytes, and a digest that is the digest of nothing this suite holds. Nothing downstream of the byte check can tell the two apart, which is why the check runs before a reader interprets a document at all.',
    envelope: originalWith(HONEST_ENVELOPE, { sha256: digestHex(TEXT('another document')) }),
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'original-bytes-stated-in-a-second-spelling',
    note: "The committed export's bytes in the other base64url spelling of the very same bytes, with the digest and the length still the digest and the length of what decodes. Every member of the record is then true of the bytes and the row is still refused for the one thing a JSON document cannot state: that a byte string has one spelling a reader reproduces.",
    envelope: originalWith(HONEST_ENVELOPE, { bytes: secondSpelling(exportBytes(HONEST)) }),
    stage: 'layout',
    code: 'NOT_IMPORT_ENVELOPE',
  },
  {
    name: 'derived-basis-of-another-original',
    note: 'A derived row naming a basis that is not the digest of the original beside it, which severs the one relationship this record exists to state. The digest is well formed and the bytes are whole; what disagrees is which original the representation claims to come from.',
    envelope: derivedWith(HONEST_ENVELOPE, { basis: digestHex(TEXT('another original')) }),
    stage: 'layout',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'derived-bytes-not-what-the-rule-produces',
    note: "A derived row that is self-consistent about its own bytes and is not what the transformation it names produces: the digest and the length are restated for the replacement bytes, so no stated digest is violated and only the re-derivation catches it. This is the reading's own check, and it is the one no schema and no digest recomputation over the record alone could make.",
    envelope: derivedWith(HONEST_ENVELOPE, {
      bytes: toBase64Url(OTHER_DERIVED),
      sha256: digestHex(OTHER_DERIVED),
      byteCount: OTHER_DERIVED.length,
    }),
    stage: 'reading',
    code: 'EVIDENCE_DIGEST_MISMATCH',
  },
  {
    name: 'export-value-a-rule-does-not-read',
    note: "An envelope whose export states `'yesterday'` at `issued`, where the rule reads a whole number of unix seconds. The position is one this reading knows and its value is one no rule reads, so the normalized document would have to omit a field the export did state: the reading refuses rather than reporting, and the refusal names the position and the shape the rule reads there.",
    envelope: UNREADABLE_ENVELOPE,
    stage: 'reading',
    code: 'NOT_IMPORT_ENVELOPE',
  },
  {
    name: 'derived-list-empty',
    note: 'An envelope whose `derived` list states nothing. An import that derived nothing is not an import this record can describe, and an empty list would let a writer reach the shape of this document without stating any representation at all.',
    envelope: { ...HONEST_ENVELOPE, derived: [] },
    stage: 'layout',
    code: 'NOT_IMPORT_ENVELOPE',
  },
];

/** The synthetic export as it is committed, held to the envelope's original and to the rules. */
function writeExportFile(): Uint8Array {
  const bytes = exportBytes(HONEST);
  mkdirSync(EXPORTS, { recursive: true });
  writeFileSync(join(EXPORTS, 'provider-export-v1.json'), bytes);
  const committed = new Uint8Array(readFileSync(join(EXPORTS, 'provider-export-v1.json')));
  if (toHex(committed) !== toHex(bytes)) throw new Error('the committed export file is not the bytes this generator wrote');
  return committed;
}

function main(): void {
  const committed = writeExportFile();
  // The committed export carries no position the shipped rules do not read, or the honest row would
  // publish a report this suite calls empty over an export that carries more than the rules know.
  const honestReport = normalizeProviderExport(committed).report;
  if (honestReport.length > 0) {
    throw new Error(`the committed export carries ${String(honestReport.length)} positions the rules do not read`);
  }
  // The envelope's original is the committed file, byte for byte, and the second intake is that same
  // original under another stamp: the pair is what the twice-import claim is made of.
  for (const row of ACCEPTED) {
    if (row.exportEdit === undefined && String(originalOf(row.envelope)['bytes']) !== toBase64Url(committed)) {
      throw new Error(`${row.name} states an original that is not the committed export, and names no edit`);
    }
    if (row.exportEdit !== undefined && String(originalOf(row.envelope)['bytes']) === toBase64Url(committed)) {
      throw new Error(`${row.name} names an edit and states the committed export unchanged`);
    }
  }
  const first = ACCEPTED[0]!;
  const again = ACCEPTED[1]!;
  const firstKey = importEnvelopeKey(parseImportEnvelope(first.envelope));
  if (again.againOf !== first.name) throw new Error('the second intake does not name the row it is a second intake of');
  const againKey = importEnvelopeKey(parseImportEnvelope(again.envelope));
  if (againKey !== firstKey) throw new Error('a second intake of one export keys as a second record');
  if (String(originalOf(again.envelope)['bytes']) !== String(originalOf(first.envelope)['bytes'])) {
    throw new Error('the second intake holds other bytes than the first');
  }
  if (String((again.envelope['imported'] as Block)['at']) === String((first.envelope['imported'] as Block)['at'])) {
    throw new Error('the second intake states no intake stamp of its own, so it states no second intake');
  }

  const vectors: Block[] = [];
  for (const row of ACCEPTED) {
    const parsed = answeredBy(() => parseImportEnvelope(row.envelope));
    const read = answeredBy(() => readImportEnvelope(row.envelope));
    if (parsed.outcome !== 'ok' || read.outcome !== 'ok') {
      throw new Error(`${row.name}: the reader refused a document this case states as taken (${parsed.outcome})`);
    }
    vectors.push({
      name: row.name,
      note: row.note,
      envelope: row.envelope,
      key: importEnvelopeKey(parseImportEnvelope(row.envelope)),
      ...(row.againOf === undefined ? {} : { againOf: row.againOf }),
      ...(row.exportEdit === undefined ? {} : { exportEdit: row.exportEdit }),
      reading: readingOf(row.envelope),
    });
  }
  // The two rows the report's two kinds are proven by, told apart here rather than only in prose.
  const unsupported = vectors.find((row) => row['name'] === 'unsupported-field-export')!;
  const missing = vectors.find((row) => row['name'] === 'missing-field-export')!;
  const unsupportedRows = (unsupported['reading'] as Block)['report'] as readonly ImportReportRow[];
  const missingRows = (missing['reading'] as Block)['report'] as readonly ImportReportRow[];
  const unsupportedRow = unsupportedRows[0];
  const missingRow = missingRows[0];
  if (unsupportedRow?.kind !== 'unsupported-field' || missingRow?.kind !== 'missing-field') {
    throw new Error('the unsupported and missing cases no longer carry one row of their own kind');
  }
  if (unsupportedRow.states === missingRow.states) {
    throw new Error('the two kinds of report row carry one sentence, so they are not distinguished');
  }

  const refusals: Block[] = [];
  for (const row of REFUSALS) {
    const parsed = answeredBy(() => parseImportEnvelope(row.envelope));
    const read = answeredBy(() => readImportEnvelope(row.envelope));
    if (row.stage === 'layout') {
      if (parsed.outcome !== row.code) {
        throw new Error(`${row.name}: the layout answers ${parsed.outcome}, not the ${row.code} this case states`);
      }
      if (read.outcome !== row.code || read.message !== parsed.message) {
        throw new Error(`${row.name}: the two published steps gave two answers for one fault`);
      }
      refusals.push({ name: row.name, note: row.note, envelope: row.envelope, stage: 'layout', code: read.outcome, message: read.message });
      continue;
    }
    if (parsed.outcome !== 'ok') {
      throw new Error(`${row.name}: the layout refused a document this case states the reading refuses`);
    }
    if (read.outcome !== row.code) {
      throw new Error(`${row.name}: the reading answers ${read.outcome}, not the ${row.code} this case states`);
    }
    refusals.push({ name: row.name, note: row.note, envelope: row.envelope, stage: 'reading', code: read.outcome, message: read.message });
  }

  const names = [...vectors, ...refusals].map((row) => String(row['name']));
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  if (vectors.length < 4) throw new Error(`${String(vectors.length)} accepted rows, and the report's states are more than that`);
  if (refusals.length < 8) throw new Error(`${String(refusals.length)} refusals, and the reading names more faults than that`);

  const keyMaterialNote = 'none: nothing in this suite is signed, so no key and no seed is published. The envelope states `signedByProvider` as false on every row, because the synthetic provider signs nothing and a record that claimed a signature nothing could later check would be the claim this layout exists to keep separated from evidence.';

  writeFileSync(
    join(DATA, 'import-v1.json'),
    `${JSON.stringify(
      {
        version: 1,
        description:
          "Import envelopes and the answer the published reader gives them: one synthetic provider export's exact bytes held as they arrived, the derived representation the shipped normalization produced from them with its label, its transformation and its basis, the deterministic report of every position the rules do not read, a second intake of one export keyed to the same record, and the refusals in between. Every row states one envelope and, where the row is accepted, what `readImportEnvelope` of `@ashaveri/sdk` answered for it when this file was written: the report rows, the digest computed over the stored bytes it hands back, the digest of what the rules produce, and the derived row the reading accepted. The refused rows state the code, the sentence, and which of the two published steps gave them, `layout` where `parseImportEnvelope` refused the document and `reading` where the layout took the bytes and the refusal came from the normalization or the re-derivation. The import envelope is keyed by `importEnvelopeKey`, sha256 under the domain prefix `ashaveri/import-v1 ` of the canonical JSON of the version, the provider and the original, so the row that states a second intake of one export carries its own envelope and the key of the first.",
        layout: {
          format:
            'the record one provider export is held in as imported: the exact bytes, the provider\'s own names, our intake stamp, and the derived representations, each labeled with the transformation that produced it and the digest of the original it rests on',
          schema:
            'packages/sdk/schemas/import-v1.schema.json, published as https://ashaveri.com/schemas/import-v1.json, which is what an importer outside this repository builds a writer against and the half of the layout that binds what a document is made of',
          prose: 'docs/import-v1.md',
          reader:
            'parseImportEnvelope in @ashaveri/sdk, which is the layout, and readImportEnvelope, which parses and then runs the reading: the shipped normalization over the original\'s bytes, the re-derivation of every derived representation against the digest the record states, and the recomputed report',
          normalization:
            'normalizeProviderExport in @ashaveri/sdk, which folds the five named rules into the normalized document; the derived row of every accepted envelope here is that function\'s output over the envelope\'s own original bytes',
          keying:
            'importEnvelopeKey in @ashaveri/sdk: sha256, under the domain prefix `ashaveri/import-v1 `, of the canonical JSON of the version, the provider block and the original block. The intake stamp and the derived rows are outside it, which is what makes the second intake of one export key like the first and the record one rather than two',
          exportFile:
            'packages/fixtures/data/exports/provider-export-v1.json, the synthetic provider\'s export, whose top-level members are `provider`, `export_id`, `issued`, `model` and `completions`, each entry of `completions` carrying `ref`, `sha256` and `at`. The accepted rows state these bytes as their original unless the row states an `exportEdit`',
          encodings:
            'byte strings inside an envelope unpadded base64url, digests lowercase hex, instants unix seconds, and the envelope itself published inline as the JSON object the reader is handed rather than as its bytes, because an envelope is read as a document and its claims live inside its members',
          codes: [...new Set(refusals.map((row) => String(row['code'])))].sort(),
          keyMaterial: keyMaterialNote,
          notChecked:
            'an envelope states which bytes were taken in and what the estate derived from them. Nothing here shows that the provider produced them, that the provider signed anything, or that the provider\'s names belong to anybody: the provider\'s signature travels in the provider\'s own framing and is walked by an adapter with the provider\'s roots, and no adapter is part of this repository.',
        },
        vectors,
        refusals,
      },
      null,
      2,
    )}\n`,
  );

  for (const row of vectors) console.log(`${String(row['name'])}: accepted, key ${String(row['key'])}`);
  for (const row of refusals) console.log(`${String(row['name'])}: ${String(row['stage'])} ${String(row['code'])}`);
}

main();
