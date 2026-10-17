import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DERIVED_REPRESENTATION_KINDS,
  IMPORT_TRANSFORMATIONS,
  ReceiptError,
  SdkError,
  fromBase64Url,
  importEnvelopeKey,
  parseImportEnvelope,
  readImportEnvelope,
  toBase64Url,
  toHex,
} from '@ashaveri/sdk';
import { describe, expect, it } from 'vitest';
import { DATA } from '../src/index.js';
import { readSourceFile, unionMembers } from './doc-contract.js';

/**
 * The published import envelope vectors, replayed the way a port replays them: take the envelope out of
 * the file, hand it to the two published steps, and compare the answer with the answer the file states.
 * Nothing here computes an expected reading out of a rule written again in this file; the reports, the
 * two digests, the derived rows, the keys and the refusal sentences are data in `data/import-v1.json`,
 * and the only question asked of the shipped code is whether it answers as the file says it does. Each
 * published row is a test of its own, so a row that is not replayed has to be skipped rather than
 * silently pass.
 *
 * Four more things are checked on the way. The first is that every refusal really refuses at the step the
 * row names, because a reader that took a document a row states as refused would leave that row silent
 * and a refusal moved from the layout to the reading would leave the row describing a fault it does not
 * have. The second is that no code the shipped reader raises is left unreached, read out of the two source
 * files rather than copied here. The third is that the bytes this suite imports are the bytes the package
 * already publishes: every accepted row that names no edit is required to state
 * `data/exports/provider-export-v1.json` as its original byte for byte, and the second intake of the
 * honest row is required to hold the same original as the first and to key like it. The fourth is that
 * every derived representation a row carries is labeled, names a transformation the version implements,
 * and rests on the digest of the original beside it.
 */

const file = JSON.parse(readFileSync(join(DATA, 'import-v1.json'), 'utf8')) as ImportVectorFile;
const EXPORT_FILE = join(DATA, 'exports', 'provider-export-v1.json');
const VECTORS_DOC = fileURLToPath(new URL('../../../docs/vectors.md', import.meta.url));
const ENVELOPE_SOURCE = '../../sdk/src/import-envelope.ts';
const NORMALIZE_SOURCE = '../../sdk/src/import-normalize.ts';
const SDK_ERRORS = '../../sdk/src/errors.ts';
const RECEIPT_ERRORS = '../../receipt/src/errors.ts';
/** The five members import version one defines, which is the closure every row of this suite is read under. */
const ENVELOPE_MEMBERS = ['v', 'provider', 'original', 'imported', 'derived'];

interface ImportVectorFile {
  readonly version: number;
  readonly description: string;
  readonly layout: {
    readonly codes: readonly string[];
    readonly schema: string;
    readonly prose: string;
    readonly reader: string;
    readonly normalization: string;
    readonly keying: string;
    readonly exportFile: string;
    readonly [key: string]: unknown;
  };
  readonly vectors: readonly AcceptedRow[];
  readonly refusals: readonly RefusalRow[];
}

interface Row {
  readonly name: string;
  readonly note: string;
  readonly envelope: Record<string, unknown>;
}

interface AcceptedRow extends Row {
  /** The key a store takes this record under, stated on the accepted rows because a refused one is held nowhere. */
  readonly key: string;
  readonly againOf?: string;
  readonly exportEdit?: string;
  readonly reading: {
    readonly report: readonly Record<string, unknown>[];
    readonly originalSha256: string;
    readonly normalizedSha256: string;
    readonly derived: readonly Record<string, unknown>[];
  };
}

interface RefusalRow extends Row {
  readonly stage: 'layout' | 'reading';
  readonly code: string;
  readonly message: string;
}

/** Every published row, tagged with the direction it states, which is what a per-row test dispatches on. */
type Replay =
  | { readonly kind: 'accepted'; readonly name: string; readonly row: AcceptedRow }
  | { readonly kind: 'refusal'; readonly name: string; readonly row: RefusalRow };

const replays: readonly Replay[] = [
  ...file.vectors.map((one): Replay => ({ kind: 'accepted', name: one.name, row: one })),
  ...file.refusals.map((one): Replay => ({ kind: 'refusal', name: one.name, row: one })),
];

const bytes = (base64url: string): Uint8Array => fromBase64Url(base64url);

const originalOf = (envelope: Record<string, unknown>): Record<string, unknown> =>
  envelope['original'] as Record<string, unknown>;

/** What a shipped step answered: its code and its sentence, or `ok` where it answered by handing something back. */
function answered(run: () => unknown): { readonly outcome: string; readonly message: string } {
  try {
    run();
    return { outcome: 'ok', message: '' };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { outcome: err.code, message: err.message };
    throw err;
  }
}

function acceptedNamed(name: string): AcceptedRow {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`data/import-v1.json publishes no accepted row named ${name}`);
  return found;
}

function refusalNamed(name: string): RefusalRow {
  const found = file.refusals.find((one) => one.name === name);
  if (found === undefined) throw new Error(`data/import-v1.json publishes no refusal named ${name}`);
  return found;
}

/** The Import envelope bullet of `docs/vectors.md`, read as one run of prose because its sentences wrap. */
function importBullet(): string {
  const doc = readFileSync(VECTORS_DOC, 'utf8');
  const start = doc.indexOf('\n- **Import envelope.');
  if (start < 0) throw new Error('docs/vectors.md states no Import envelope bullet to read');
  const end = doc.indexOf('\n## ', start);
  return doc.slice(start, end < 0 ? undefined : end).replace(/\n\s*/gu, ' ');
}

/** One count that bullet states about these rows, taken back out of the sentence that states it. */
function countInBullet(states: RegExp, what: string): number {
  const stated = states.exec(importBullet());
  if (stated === null) throw new Error(`the Import envelope bullet of docs/vectors.md states no count of ${what}`);
  return Number(stated[1]);
}

/**
 * The codes the two published source files raise themselves, read out of the call forms that name one
 * rather than copied into this file. A code the reader raises and no row reaches is a refusal published
 * nowhere, which is the state a vector family has to be re-run into rather than re-remembered into.
 */
function codesTheReaderRaises(): string[] {
  const source = `${readSourceFile(ENVELOPE_SOURCE)}\n${readSourceFile(NORMALIZE_SOURCE)}`;
  const patterns = [
    /refused\(\s*'([A-Z][A-Z0-9_]+)'/gu,
    /new SdkError\(\s*'([A-Z][A-Z0-9_]+)'/gu,
    /new ReceiptError\(\s*'([A-Z][A-Z0-9_]+)'/gu,
  ];
  const found = patterns.flatMap((pattern) => [...source.matchAll(pattern)].map((each) => each[1]!));
  return [...new Set(found)].sort();
}

describe('data/import-v1.json', () => {
  it('states a rule in prose, names the two readers it is read by, and publishes both directions', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(80);
    expect(file.layout.schema).toContain('packages/sdk/schemas/import-v1.schema.json');
    expect(file.layout.prose).toBe('docs/import-v1.md');
    expect(file.layout.reader).toContain('parseImportEnvelope');
    expect(file.layout.reader).toContain('readImportEnvelope');
    expect(file.layout.normalization).toContain('normalizeProviderExport');
    expect(file.vectors.length, 'a suite with too few accepted rows cannot state what an import is').toBeGreaterThanOrEqual(4);
    expect(file.refusals.length, 'a suite of accepted rows proves nothing about a reader\'s refusals').toBeGreaterThanOrEqual(8);
    for (const code of file.layout.codes) {
      expect(file.refusals.some((one) => one.code === code), `${code} is listed and refused by no row`).toBe(true);
    }
  });

  it.each(replays)('$name replays as the file says', (one) => {
    const parsed = answered(() => parseImportEnvelope(one.row.envelope));
    const reading = answered(() => readImportEnvelope(one.row.envelope));
    if (one.kind === 'accepted') {
      const row = one.row;
      expect(parsed.outcome, `${row.name}: the layout refused a row this file publishes as taken`).toBe('ok');
      expect(reading.outcome, `${row.name}: the reading refused a row this file publishes as taken`).toBe('ok');
      const seen = readImportEnvelope(row.envelope);
      // The report the row publishes is the report the shipped rules gave it, row by row and in order.
      expect(seen.report, `${row.name}: a different report for the same export`).toEqual(row.reading.report);
      // The two halves the file publishes: the digest over the bytes the reader hands back, and the digest
      // of what the rules produce, which every derived row has to state.
      expect(seen.repeated.sha256, `${row.name}: a different digest over the stored bytes`).toBe(row.reading.originalSha256);
      expect(seen.repeated.normalizedSha256, `${row.name}: a different digest over what the rules produce`).toBe(
        row.reading.normalizedSha256,
      );
      expect(seen.stated.derived, `${row.name}: a different derived row than the file states`).toEqual(row.reading.derived);
      expect(importEnvelopeKey(parseImportEnvelope(row.envelope)), `${row.name}: a different key for the same record`).toBe(
        row.key,
      );
      return;
    }
    const row = one.row;
    expect(reading.outcome, `${row.name}: the reader took a document this row states as refused`).not.toBe('ok');
    const given = parsed.outcome === 'ok' ? reading : parsed;
    expect(given.outcome, `${row.name}: the reader answers ${given.outcome}, not the ${row.code} the file states`).toBe(
      row.code,
    );
    expect(given.message, `${row.name}: this reader gave the refusal in other words than the file states`).toBe(
      row.message,
    );
  });

  it('refuses every published refusal at the step the row names', () => {
    for (const row of file.refusals) {
      const parsed = answered(() => parseImportEnvelope(row.envelope));
      const reading = answered(() => readImportEnvelope(row.envelope));
      if (row.stage === 'layout') {
        expect(parsed.outcome, `${row.name}: the layout took a document this row states it refuses`).not.toBe('ok');
        expect(parsed.outcome, `${row.name}: the layout answered another code than the row states`).toBe(row.code);
        // `readImportEnvelope` parses, so a layout refusal reaches it as the same refusal and no further.
        expect(reading.outcome, `${row.name}: the reading answered before the layout had`).toBe(row.code);
        expect(reading.message, `${row.name}: the two published steps gave two sentences for one fault`).toBe(row.message);
        continue;
      }
      expect(parsed.outcome, `${row.name}: the layout refused the document this row states the reading refuses`).toBe('ok');
      expect(reading.outcome, `${row.name}: the reading took a document this row states it refuses`).toBe(row.code);
      expect(reading.message, `${row.name}: the reading gave another sentence than the row states`).toBe(row.message);
    }
  });

  it('reaches every code the reader raises and names no code no registry declares', () => {
    const raised = codesTheReaderRaises();
    expect(raised.length, 'the reader sources name no code, so this check guards nothing').toBeGreaterThanOrEqual(3);
    const reached = new Set(file.refusals.map((one) => one.code));
    for (const code of raised) {
      expect(reached.has(code), `${code} is raised by the shipped reader and no published row reaches it`).toBe(true);
    }
    const declared = new Set([
      ...unionMembers('SdkErrorCode', SDK_ERRORS),
      ...unionMembers('ReceiptErrorCode', RECEIPT_ERRORS),
    ]);
    const undeclared = [...reached].filter((code) => !declared.has(code));
    expect(undeclared, 'a published refusal names a code no registry declares').toEqual([]);
    expect([...reached].sort(), 'the codes the rows refuse with and the list the file publishes').toEqual(
      [...file.layout.codes].sort(),
    );
  });

  it('imports the committed synthetic export twice as one record, with the bytes unchanged', () => {
    const first = acceptedNamed('honest-export-imported');
    const again = acceptedNamed('honest-export-imported-again');
    expect(again.againOf, 'the second intake does not name the row it repeats').toBe(first.name);
    // The committed export is the first row's original, byte for byte, and the second intake holds it too.
    const committed = new Uint8Array(readFileSync(EXPORT_FILE));
    expect(toHex(bytes(String(originalOf(first.envelope)['bytes']))), 'the imported bytes are not the committed export').toBe(
      toHex(committed),
    );
    expect(String(originalOf(again.envelope)['bytes']), 'the second intake holds other bytes than the first').toBe(
      String(originalOf(first.envelope)['bytes']),
    );
    // Two intakes, one record: the stamps differ and the keys do not.
    expect(again.envelope['imported']).not.toEqual(first.envelope['imported']);
    expect(again.key, 'a second intake of one export keyed as a second record').toBe(first.key);
    // And every accepted row that names no edit states those committed bytes as its original.
    for (const row of file.vectors) {
      const statesExport = String(originalOf(row.envelope)['bytes']) === toBase64Url(committed);
      if (row.exportEdit === undefined) {
        expect(statesExport, `${row.name}: names no edit and states an original other than the committed export`).toBe(true);
      } else {
        expect(statesExport, `${row.name}: names an edit and states the committed export unchanged`).toBe(false);
      }
    }
  });

  it('keeps the two report kinds apart, one per row the pair is proven by', () => {
    const unsupported = acceptedNamed('unsupported-field-export');
    const missing = acceptedNamed('missing-field-export');
    expect(unsupported.reading.report).toHaveLength(1);
    expect(missing.reading.report).toHaveLength(1);
    const carried = unsupported.reading.report[0]!;
    const absent = missing.reading.report[0]!;
    expect(carried['kind']).toBe('unsupported-field');
    expect(absent['kind']).toBe('missing-field');
    expect(carried['field']).not.toBe(absent['field']);
    expect(carried['states']).not.toBe(absent['states']);
    // The same export throws the same sentence every time it is read, and reading is a function of the
    // bytes rather than of the envelope's member order: a re-spelled envelope reports the same rows.
    const respelled: Record<string, unknown> = {};
    for (const member of Object.keys(unsupported.envelope).reverse()) respelled[member] = unsupported.envelope[member];
    expect(readImportEnvelope(respelled).report).toEqual(unsupported.reading.report);
    expect(importEnvelopeKey(parseImportEnvelope(respelled))).toBe(unsupported.key);
  });

  it('labels every derived representation and keeps the original beside it', () => {
    expect([...DERIVED_REPRESENTATION_KINDS]).toEqual(['normalized-export']);
    expect([...IMPORT_TRANSFORMATIONS]).toEqual(['normalizeProviderExport']);
    for (const row of file.vectors) {
      const parsed = parseImportEnvelope(row.envelope);
      const seen = readImportEnvelope(row.envelope);
      const stored = bytes(String(originalOf(row.envelope)['bytes']));
      expect(toHex(seen.repeated.originalBytes), `${row.name}: the reader handed back other bytes than it holds`).toBe(
        toHex(stored),
      );
      expect(seen.repeated.sha256, `${row.name}: the digest recomputed is not the digest of the stored bytes`).toBe(
        toHex(sha256(stored)),
      );
      expect(parsed.derived.length, `${row.name}: an accepted envelope with no derived representation`).toBeGreaterThan(0);
      for (const derived of parsed.derived) {
        expect((DERIVED_REPRESENTATION_KINDS as readonly string[]).includes(derived.k), `${row.name}: an unlabeled kind`).toBe(true);
        expect((IMPORT_TRANSFORMATIONS as readonly string[]).includes(derived.derivedBy), `${row.name}: an unknown rule`).toBe(true);
        expect(derived.basis, `${row.name}: the derived row rests on another original`).toBe(toHex(sha256(stored)));
        expect(seen.repeated.normalizedSha256, `${row.name}: the derived row is not the rule's output`).toBe(derived.sha256);
      }
    }
  });

  it('keys the accepted exports apart, and an intake of one export like the export it repeats', () => {
    const independent = file.vectors.filter((row) => row.againOf === undefined);
    const keys = independent.map((row) => row.key);
    expect(new Set(keys).size, 'two accepted rows of one export key alike').toBe(keys.length);
    // The second intake is the one row that keys like another, and it names the row it repeats.
    for (const row of file.vectors) {
      if (row.againOf === undefined) continue;
      expect(row.key, `${row.name}: an intake that keys apart from the row it repeats`).toBe(acceptedNamed(row.againOf).key);
    }
  });

  it('states one whole envelope per row, read under the members version one defines', () => {
    for (const one of replays) {
      // One row carries a member the version does not define, and it is the row that names it.
      if (one.name === 'member-import-version-one-does-not-define') {
        const extras = Object.keys(one.row.envelope).filter((member) => !ENVELOPE_MEMBERS.includes(member));
        expect(extras, `${one.name}: the row that carries an undefined member no longer carries exactly one`).toEqual([
          'retainedAt',
        ]);
      } else {
        for (const member of Object.keys(one.row.envelope)) {
          expect(ENVELOPE_MEMBERS, `${one.name} carries a member import version one does not define: ${member}`).toContain(member);
        }
      }
      // One row states a version this layout has no reader for, and it is the row that names it.
      expect(one.row.envelope['v'], `${one.name}: a row that names no import version`).toBe(
        one.name === 'version-two' ? 2 : 1,
      );
      expect(one.row.note.length, `${one.name}: a row with no sentence about what it turns on`).toBeGreaterThan(60);
      // A refused envelope is one a store refuses to hold, so a key is stated on the accepted rows only.
      if (one.kind === 'accepted') {
        expect(one.row.key, `${one.name}: an accepted row with no key`).toMatch(/^[0-9a-f]{64}$/u);
      } else {
        expect((one.row as Partial<AcceptedRow>).key, `${one.name}: a refused row states a key`).toBeUndefined();
      }
    }
  });

  it('names the export file the accepted rows state, and the file is the synthetic provider\'s', () => {
    const committed = JSON.parse(readFileSync(EXPORT_FILE, 'utf8')) as Record<string, unknown>;
    expect(file.layout.exportFile).toContain('packages/fixtures/data/exports/provider-export-v1.json');
    expect(Object.keys(committed).sort()).toEqual(['completions', 'export_id', 'issued', 'model', 'provider']);
    expect(refusalNamed('original-bytes-stated-in-a-second-spelling').code).toBe('NOT_IMPORT_ENVELOPE');
  });

  it('names in its document the counts its rows carry', () => {
    expect(
      countInBullet(/publishes ([0-9]+) accepted rows/u, 'the accepted rows'),
      'docs/vectors.md counts a different number of accepted rows than the file publishes',
    ).toBe(file.vectors.length);
    expect(
      countInBullet(/and ([0-9]+) refusals/u, 'the refusals'),
      'docs/vectors.md counts a different number of refusals than the file publishes',
    ).toBe(file.refusals.length);
  });
});
