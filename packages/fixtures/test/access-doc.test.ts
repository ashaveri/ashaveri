import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { renderAccessLine, type AccessRecord } from '@ashaveri/signerd';
import { loadPopVectors } from '../src/index.js';
import { spelledNumber, tableRows } from './doc-contract.js';

const DOC = fileURLToPath(new URL('../../../docs/access-control.md', import.meta.url));
const MARKER = '<!-- pop-signing-string:completion-post -->';
/** The header of the one table that lists the access record's fields, one row per field. */
const FIELD_TABLE = '| Field | Purpose |';

/**
 * A request that reached the end of the pipeline with everything the record can hold: a named
 * credential, a scope, a receipt, a nonce, and a refusal the log recorded and the caller was not
 * told. Every field carries a value because a field the fixture left unbound would drop out of the
 * rendered object, and a document row for it would then be read as an over-long allowlist rather
 * than as what it is.
 */
const WRITTEN: AccessRecord = {
  t: 1_772_000_000_000,
  rid: 'rid-9f2b1c7d',
  cred: 'svc-1',
  auth: 'pop',
  scope: 'read',
  m: 'GET',
  p: '/v1/receipts/9f2b1c7d4e5a6b7c8d9e0f1a2b3c4d5e',
  rcp: '9f2b1c7d4e5a6b7c8d9e0f1a2b3c4d5e',
  nce: 'UFdDxyVjlgySSGS0GFRbMg',
  st: 200,
  dur: 41,
  deny: 'AUTH_UNKNOWN',
};

/**
 * What the deployer's tooling actually receives. The field names and their order exist together in
 * exactly one place: the object `renderAccessLine` writes. The interface is compile-time only, and
 * the array behind the writer is one of the two things under test, so neither can be the yardstick
 * the document is measured against.
 */
function fieldsTheWriterEmits(): string[] {
  return Object.keys(JSON.parse(renderAccessLine(WRITTEN)) as Record<string, unknown>);
}

function documentText(): string {
  return readFileSync(DOC, 'utf8');
}

/** The field names as the allowlist table rows carry them, backticks already trimmed away. */
function fieldsTheDocumentNames(): string[] {
  // A row's first cell is the empty string before the leading pipe, so the name is in cell 1.
  return tableRows(documentText(), FIELD_TABLE).map((cells) => cells[1]?.replace(/`/gu, '') ?? '');
}

describe('docs/access-control.md', () => {
  it('shows the signing string the golden vector signs, byte for byte', () => {
    const text = documentText();
    const at = text.indexOf(MARKER);
    expect(at, `${MARKER} must sit above the worked example`).toBeGreaterThan(-1);
    const block = /```text\n([\s\S]*?)```/u.exec(text.slice(at));
    expect(block, 'the worked example is a fenced text block').not.toBeNull();
    const [vector] = loadPopVectors().vectors;
    expect(block?.[1]?.replace(/\n$/u, '')).toBe(vector?.signingString);
  });

  it('names every field the writer emits, and names nothing the writer does not emit', () => {
    // The comparison is both directions at once, because the document can drift from the line in
    // either: a field the writer gained with no row here leaves a deployer's parser blind to a key
    // that is on the volume, and a row for a field nothing writes teaches a tool to ask for a key
    // that never arrives. A membership list copied into this test would have caught neither, since
    // the copy drifts with the document rather than with the code.
    expect(fieldsTheDocumentNames().sort(), 'the allowlist table against the rendered line').toEqual(
      fieldsTheWriterEmits().sort(),
    );
  });

  it('names them in the order the writer emits them', () => {
    // The section promises "in the order the writer emits them", and the file is line-oriented
    // JSONL, so a reader that counts positions rather than keys is reading this order. Reordering
    // the table, or the writer, keeps the two name sets equal and is invisible to the check above.
    expect(fieldsTheDocumentNames(), 'the allowlist table against the rendered line').toEqual(
      fieldsTheWriterEmits(),
    );
  });

  it('states above the table how many fields it has', () => {
    // A table can gain a row in step with the writer and still leave its own lead-in counting the
    // old total, which is the one number in the section a reader checks the rows against without
    // opening the code.
    const stated = /The (\w+) fields, in the order the writer emits them/u.exec(documentText());
    expect(stated, 'the sentence above the allowlist table states a count').not.toBeNull();
    expect(spelledNumber(stated?.[1] ?? ''), 'the count the sentence states').toBe(
      fieldsTheWriterEmits().length,
    );
  });
});
