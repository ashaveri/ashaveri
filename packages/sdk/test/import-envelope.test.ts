import { describe, expect, it } from 'vitest';
import { equalBytes, ReceiptError, toBase64Url, toHex } from '@ashaveri/receipt';
import { sha256 } from '@noble/hashes/sha2.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { fromBase64Url } from '../src/b64.js';
import { SdkError } from '../src/errors.js';
import {
  DERIVED_REPRESENTATION_KINDS,
  IMPORT_FORMAT_VERSION,
  importEnvelopeKey,
  IMPORT_TRANSFORMATIONS,
  parseImportEnvelope,
  readImportEnvelope,
} from '../src/import-envelope.js';
import { normalizeProviderExport } from '../src/import-normalize.js';

/**
 * The import envelope read as a document: the record a store keys on, the two published steps, and the
 * schema beside them.
 *
 * The synthetic provider export these envelopes hold is built here the way the fixture suite builds its
 * own, and the derived representation inside each accepted envelope is the shipped normalization's output
 * rather than a hand-written copy, so every accepted case stands on the code that will be run over it.
 * The refusals are one edit each, and each edit names the rule it turns on.
 */

const TEXT = (value: string): Uint8Array => new TextEncoder().encode(value);
const DIGEST_A = 'ab'.repeat(32);
const DIGEST_B = 'cd'.repeat(32);
const IMPORTED_AT = 1_759_280_000;

function entry(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { ref: 'c-0001', sha256: DIGEST_A, at: 1_759_276_701, ...over };
}

/** The synthetic provider's export: every member a rule reads, two whole entries, nothing else. */
function honestExport(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    provider: 'synthhub',
    export_id: 'EXP-2026-10-01-0001',
    issued: 1_759_276_800,
    model: 'synth-model-1',
    completions: [entry(), entry({ ref: 'c-0002', sha256: DIGEST_B, at: 1_759_276_752 })],
    ...over,
  };
}

function without(exported: Record<string, unknown>, ...members: readonly string[]): Record<string, unknown> {
  const out = { ...exported };
  for (const member of members) delete out[member];
  return out;
}

/** The envelope one export imports as, with the derived representation taken out of the shipped rules. */
function envelopeFor(exported: Record<string, unknown>, over: Record<string, unknown> = {}): Record<string, unknown> {
  const bytes = TEXT(JSON.stringify(exported));
  const derived = normalizeProviderExport(bytes).bytes;
  return {
    v: IMPORT_FORMAT_VERSION,
    provider: {
      name: typeof exported['provider'] === 'string' ? exported['provider'] : 'synthhub',
      exportId: typeof exported['export_id'] === 'string' ? exported['export_id'] : 'EXP-2026-10-01-0001',
    },
    original: {
      bytes: toBase64Url(bytes),
      sha256: toHex(sha256(bytes)),
      byteCount: bytes.length,
      signedByProvider: false,
    },
    imported: { at: IMPORTED_AT },
    derived: [
      {
        k: 'normalized-export',
        derivedBy: 'normalizeProviderExport',
        basis: toHex(sha256(bytes)),
        bytes: toBase64Url(derived),
        sha256: toHex(sha256(derived)),
        byteCount: derived.length,
      },
    ],
    ...over,
  };
}

/** The envelope as the second intake of one export: the block that differs is the one the key excludes. */
function envelopeImportedAgain(exported: Record<string, unknown>): Record<string, unknown> {
  return envelopeFor(exported, { imported: { at: IMPORTED_AT + 86_400 } });
}

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

/** The envelope with its single derived row's import replaced wholesale, which is how a second row is made. */
function withDerived(envelope: Block, rows: readonly Block[]): Block {
  return { ...envelope, derived: rows };
}

/** The refusal one run answers with, as the code and the sentence a reader branches on. */
function refusalOf(run: () => unknown): { readonly code: string; readonly message: string } {
  try {
    run();
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { code: err.code, message: err.message };
    throw err;
  }
  throw new Error('the run answered with a value where this case states a refusal');
}

/**
 * The other base64url spelling of the same bytes, by moving a tail bit no part of the document occupies.
 * It refuses to answer unless the move decodes back to the same bytes, so a case built on it states the
 * one fault it names rather than a byte string that decodes to something else.
 */
function secondSpelling(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const canonical = toBase64Url(bytes);
  const last = canonical[canonical.length - 1]!;
  const spelled = `${canonical.slice(0, -1)}${alphabet[alphabet.indexOf(last) + 1]!}`;
  if (!equalBytes(fromBase64Url(spelled), bytes) || toBase64Url(fromBase64Url(spelled)) !== canonical) {
    throw new Error(`${spelled} is not a second spelling of these ${String(bytes.length)} bytes`);
  }
  return spelled;
}

describe('a reading of the honest envelope', () => {
  it('hands the stored bytes back unchanged and reports the two halves apart', () => {
    const exported = honestExport();
    const envelope = envelopeFor(exported);
    const reading = readImportEnvelope(envelope);
    const bytes = TEXT(JSON.stringify(exported));
    expect(equalBytes(reading.repeated.originalBytes, bytes), 'the reader did not hand back the stored bytes').toBe(true);
    expect(reading.repeated.sha256).toBe(toHex(sha256(bytes)));
    expect(reading.stated.provider).toEqual({ name: 'synthhub', exportId: 'EXP-2026-10-01-0001' });
    expect(reading.stated.importedAt).toBe(IMPORTED_AT);
    expect(reading.stated.signedByProvider).toBe(false);
    expect(reading.report).toEqual([]);
    // The derived representation is labeled, names its original, and its digest is the digest the
    // shipped rules produce from that original, which the reading recomputes for itself.
    const row = reading.stated.derived[0]!;
    expect(row.k).toBe('normalized-export');
    expect(row.derivedBy).toBe('normalizeProviderExport');
    expect(row.basis).toBe(toHex(sha256(bytes)));
    expect(reading.repeated.normalizedSha256).toBe(toHex(sha256(fromBase64Url(row.bytes))));
    expect(reading.repeated.normalizedSha256).toBe(row.sha256);
  });

  it('reports an unsupported field and a missing field, each with one sentence, the two apart', () => {
    const carried = readImportEnvelope(envelopeFor(honestExport({ region: 'eu-west-1' })));
    expect(carried.report).toEqual([
      {
        kind: 'unsupported-field',
        field: 'region',
        states: "the export carries 'region', which no normalization rule of import version 1 reads",
      },
    ]);
    const absent = readImportEnvelope(envelopeFor(without(honestExport(), 'model')));
    expect(absent.report).toEqual([
      {
        kind: 'missing-field',
        field: 'model',
        states: "the export carries nothing at 'model', which normalization rule 'normalizeModel' reads",
      },
    ]);
    // The two kinds are distinguished by kind, by field and by sentence, and neither sentence is the other.
    expect(carried.report[0]!.kind).not.toBe(absent.report[0]!.kind);
    expect(carried.report[0]!.field).not.toBe(absent.report[0]!.field);
    expect(carried.report[0]!.states).not.toBe(absent.report[0]!.states);
  });

  it('gives the same report for the same export every time it is read', () => {
    const envelope = envelopeFor(honestExport({ region: 'eu-west-1' }));
    expect(readImportEnvelope(envelope).report).toEqual(readImportEnvelope(envelope).report);
    expect(readImportEnvelope(envelopeFor(honestExport({ region: 'us-east-1' }))).report).toEqual(
      readImportEnvelope(envelope).report,
    );
  });

  it('parses without reading, and the parsed document carries the members the reading states', () => {
    const envelope = envelopeFor(honestExport());
    const parsed = parseImportEnvelope(envelope);
    expect(parsed.v).toBe(IMPORT_FORMAT_VERSION);
    expect(parsed.derived.length).toBe(1);
    expect(parsed.original.sha256).toBe(toHex(sha256(TEXT(JSON.stringify(honestExport())))));
  });
});

describe('the record identity', () => {
  it('keys importing the same export twice as one record, with one store entry to show for it', () => {
    const exported = honestExport();
    const first = envelopeFor(exported);
    const second = envelopeImportedAgain(exported);
    expect(second['imported']).not.toEqual(first['imported']);
    const firstKey = importEnvelopeKey(parseImportEnvelope(first));
    const secondKey = importEnvelopeKey(parseImportEnvelope(second));
    expect(secondKey, 'a second intake of one export keyed as a second record').toBe(firstKey);
    // The store a collector writes to keys on this digest, and two intakes write one entry.
    const store = new Map<string, unknown>();
    store.set(firstKey, first);
    store.set(secondKey, second);
    expect(store.size).toBe(1);
    // And both readings hand back byte-identical preserved originals.
    const bytes = TEXT(JSON.stringify(exported));
    const firstBytes = readImportEnvelope(first).repeated.originalBytes;
    const secondBytes = readImportEnvelope(second).repeated.originalBytes;
    expect(equalBytes(firstBytes, secondBytes)).toBe(true);
    expect(equalBytes(firstBytes, bytes)).toBe(true);
  });

  it('keys one export apart from another whose bytes differ by one member', () => {
    const one = importEnvelopeKey(parseImportEnvelope(envelopeFor(honestExport())));
    const other = importEnvelopeKey(parseImportEnvelope(envelopeFor(honestExport({ model: 'synth-model-2' }))));
    expect(other).not.toBe(one);
  });

  it('keys one document spelled twice as two records, because the bytes are not the same bytes', () => {
    // One export text with its members in another order: the normalization reads the two the same way,
    // and the key does not, because the key is taken over the bytes rather than over the reading.
    const exported = honestExport();
    const flipped: Block = {};
    for (const member of Object.keys(exported).sort().reverse()) flipped[member] = exported[member];
    const one = envelopeFor(exported);
    const other = envelopeFor(flipped);
    const bytesOf = (envelope: Block): string => String(originalOf(envelope)['bytes']);
    expect(bytesOf(other)).not.toBe(bytesOf(one));
    expect(importEnvelopeKey(parseImportEnvelope(other))).not.toBe(importEnvelopeKey(parseImportEnvelope(one)));
    // What one export is about does not move with the spelling, which is the reading's own rule.
    expect(readImportEnvelope(other).repeated.normalizedSha256).toBe(readImportEnvelope(one).repeated.normalizedSha256);
  });

  it('keys the content and not the intake stamp, so one export is one key however it is dated', () => {
    const envelope = envelopeFor(honestExport());
    const key = importEnvelopeKey(parseImportEnvelope(envelope));
    expect(importEnvelopeKey(parseImportEnvelope(envelopeImportedAgain(honestExport())))).toBe(key);
  });
});

describe('what the reader refuses', () => {
  it('refuses a version it does not implement, under the shared code, before reading a member', () => {
    const refused = refusalOf(() => parseImportEnvelope(envelopeFor(honestExport(), { v: 2 })));
    expect(refused.code).toBe('UNSUPPORTED_VERSION');
    expect(refused.message).toContain('version 2');
    expect(refusalOf(() => parseImportEnvelope(envelopeFor(honestExport(), { v: '1' }))).code).toBe('UNSUPPORTED_VERSION');
  });

  it('refuses a member no version defines, an absent member, and a block of the wrong shape', () => {
    for (const edited of [
      envelopeFor(honestExport(), { retainedAt: IMPORTED_AT }),
      { ...envelopeFor(honestExport()), derived: undefined },
      { ...envelopeFor(honestExport()), provider: { name: 'synthhub' } },
      originalWith(envelopeFor(honestExport()), { signedByProvider: 'no' }),
    ]) {
      expect(refusalOf(() => parseImportEnvelope(edited)).code).toBe('NOT_IMPORT_ENVELOPE');
    }
    expect(refusalOf(() => parseImportEnvelope(envelopeFor(honestExport(), { derived: [] }))).code).toBe(
      'NOT_IMPORT_ENVELOPE',
    );
  });

  it('refuses a representation or a transformation this version does not define, and two rows of one kind', () => {
    const wrongKind = refusalOf(() =>
      parseImportEnvelope(derivedWith(envelopeFor(honestExport()), { k: 'canonical-export' })),
    );
    expect(wrongKind.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(wrongKind.message).toContain("'canonical-export'");
    const wrongRule = refusalOf(() =>
      parseImportEnvelope(derivedWith(envelopeFor(honestExport()), { derivedBy: 'normalizeSomethingElse' })),
    );
    expect(wrongRule.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(wrongRule.message).toContain("'normalizeSomethingElse'");
    const twice = refusalOf(() => {
      const envelope = envelopeFor(honestExport());
      const row = derivedOf(envelope)[0]!;
      return parseImportEnvelope(withDerived(envelope, [row, row]));
    });
    expect(twice.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(twice.message).toContain('twice');
  });

  it('refuses a digest disagreement over the stored bytes, in the original and in the derived row alike', () => {
    const digest = refusalOf(() => parseImportEnvelope(originalWith(envelopeFor(honestExport()), { sha256: DIGEST_A })));
    expect(digest.code).toBe('EVIDENCE_DIGEST_MISMATCH');
    const count = refusalOf(() => parseImportEnvelope(originalWith(envelopeFor(honestExport()), { byteCount: 3 })));
    expect(count.code).toBe('EVIDENCE_DIGEST_MISMATCH');
    const derivedCount = refusalOf(() => parseImportEnvelope(derivedWith(envelopeFor(honestExport()), { byteCount: 3 })));
    expect(derivedCount.code).toBe('EVIDENCE_DIGEST_MISMATCH');
  });

  it('refuses a base64url spelling no reader reproduces, at the original and at a derived representation', () => {
    // One byte, whose short last group has free tail bits: the two spellings decode to it and only the
    // canonical one is the spelling this reader writes.
    const bytes = TEXT('x');
    const envelope = envelopeFor(honestExport());
    const original = refusalOf(() =>
      parseImportEnvelope(
        originalWith(envelope, {
          bytes: secondSpelling(bytes),
          sha256: toHex(sha256(bytes)),
          byteCount: bytes.length,
        }),
      ),
    );
    expect(original.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(original.message).toContain('base64url');
    const derived = refusalOf(() =>
      parseImportEnvelope(
        derivedWith(envelope, {
          bytes: secondSpelling(bytes),
          sha256: toHex(sha256(bytes)),
          byteCount: bytes.length,
        }),
      ),
    );
    expect(derived.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(derived.message).toContain('base64url');
  });

  it('refuses a derived row whose basis is not the digest of the original beside it', () => {
    const refused = refusalOf(() => parseImportEnvelope(derivedWith(envelopeFor(honestExport()), { basis: DIGEST_A })));
    expect(refused.code).toBe('EVIDENCE_DIGEST_MISMATCH');
    expect(refused.message).toContain('basis');
  });

  it('refuses a derived row that is not the bytes the rule it names produces', () => {
    // Self-consistent bytes: their digest and count are restated for them, so only the re-derivation of
    // the named rule can catch them, which is the check this row exists to prove.
    const other = TEXT('{"v":1}');
    const refused = refusalOf(() =>
      readImportEnvelope(
        derivedWith(envelopeFor(honestExport()), { bytes: toBase64Url(other), sha256: toHex(sha256(other)), byteCount: other.length }),
      ),
    );
    expect(refused.code).toBe('EVIDENCE_DIGEST_MISMATCH');
    expect(refused.message).toContain('produces');
  });

  it('refuses a normalization that cannot run over the export, naming the position', () => {
    // The envelope of an export whose instant is a string: the original holds that export's bytes, the
    // derived row names them as its basis, and the reading reaches the export before it compares a digest.
    const edited = envelopeFor(without(honestExport(), 'issued'));
    const bad = TEXT(JSON.stringify(honestExport({ issued: 'yesterday' })));
    const refused = refusalOf(() =>
      readImportEnvelope(
        derivedWith(originalWith(edited, { bytes: toBase64Url(bad), sha256: toHex(sha256(bad)), byteCount: bad.length }), {
          basis: toHex(sha256(bad)),
        }),
      ),
    );
    expect(refused.code).toBe('NOT_IMPORT_ENVELOPE');
    expect(refused.message).toContain("'issued'");
    // And an export that states nothing at an instant is read: the report names the position instead.
    expect(readImportEnvelope(edited).report[0]!.field).toBe('issued');
  });
});

describe('the published schema and the reader decide the same documents', () => {
  const schemaPath = fileURLToPath(new URL('../schemas/import-v1.schema.json', import.meta.url));
  const ajv = new Ajv2020({ strict: true });
  // The document read with the member lists this walk compares, so a schema that loses one stops here.
  const schemaDocument = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
    $id: string;
    required: readonly string[];
    properties: {
      v: { const: number };
      derived: {
        items: {
          required: readonly string[];
          properties: { k: { enum: readonly string[] }; derivedBy: { enum: readonly string[] } };
        };
      };
    };
  };
  const validate = ajv.compile(schemaDocument) as ValidateFunction<unknown>;

  it('accepts the honest envelope through both authorities, and refuses one edits through both', () => {
    const envelope = envelopeFor(honestExport());
    expect(validate(envelope), JSON.stringify(validate.errors)).toBe(true);
    expect(() => parseImportEnvelope(envelope)).not.toThrow();
    // A member the version does not define, a missing member, and a missing row member are refused by
    // the schema and by the reader alike, so the two authorities describe one document.
    for (const edited of [
      envelopeFor(honestExport(), { retainedAt: 1 }),
      { ...envelopeFor(honestExport()), imported: {} },
      derivedWith(envelopeFor(honestExport()), { basis: undefined }),
    ]) {
      expect(validate(edited), 'the schema took a document the reader refuses').toBe(false);
      expect(() => parseImportEnvelope(edited)).toThrow();
    }
  });

  it('holds the schema\'s two enums to the reader\'s two lists, in both directions', () => {
    const derived = schemaDocument.properties.derived.items;
    expect([...derived.properties.k.enum].sort()).toEqual([...DERIVED_REPRESENTATION_KINDS].sort());
    expect([...derived.properties.derivedBy.enum].sort()).toEqual([...IMPORT_TRANSFORMATIONS].sort());
    expect([...derived.required].sort()).toEqual(['k', 'derivedBy', 'basis', 'bytes', 'sha256', 'byteCount'].sort());
    expect([...schemaDocument.required].sort()).toEqual(['v', 'provider', 'original', 'imported', 'derived'].sort());
  });

  it('names the same version in the identity and in the document, which the schema-identity suite holds too', () => {
    expect(schemaDocument.$id).toBe('https://ashaveri.com/schemas/import-v1.json');
    expect(schemaDocument.properties.v.const).toBe(IMPORT_FORMAT_VERSION);
  });
});
