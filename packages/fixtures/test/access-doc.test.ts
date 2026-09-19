import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { renderAccessLine, type AccessRecord } from '@ashaveri/signerd';
import { loadPopVectors } from '../src/index.js';
import { literalEntries, readSourceFile, sectionBody, spelledNumber, tableRows, unionMembers } from './doc-contract.js';

const DOC = fileURLToPath(new URL('../../../docs/access-control.md', import.meta.url));
const CODES_DOC = '../../../docs/error-codes.md';
/** Where the refusal codes, their sentences and their statuses are written down as code. */
const ACCESS_SOURCE = '../../../gateway/src/access.ts';
const MARKER = '<!-- pop-signing-string:completion-post -->';
/** The header of the one table that lists the access record's fields, one row per field. */
const FIELD_TABLE = '| Field | Purpose |';
/** The header of the one table that gives each refusal the status a caller sees. */
const REFUSAL_TABLE = '| Code | HTTP | Meaning | What a client does |';
/** The header every union table in `docs/error-codes.md` carries, read inside one section only. */
const CODE_TABLE = '| Code | Union | Raised when | What the caller does | Verdict |';
const ACCESS_SECTION = '## `AccessErrorCode`';

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

/** The refusal codes as the access layer declares them, in declaration order. */
function declaredCodes(): string[] {
  return unionMembers('AccessErrorCode', ACCESS_SOURCE);
}

/** What `accessStatus` answers each declared code with, read off the map it reads. */
function statusOfEachCode(): Map<string, number> {
  return new Map(literalEntries('ERROR_STATUS', ACCESS_SOURCE).map((entry) => [entry.key, Number(entry.value)]));
}

/**
 * The codes a request is never answered with, told from the mapping rather than from a list copied
 * here: they are the 500s, the ones the access layer's own paragraph on the map explains as the file
 * the operator installed being broken, which no header a client sends can fix. `admit` raises none
 * of them; they answer where records enter the store.
 */
function codesNoRequestMeets(): string[] {
  const statuses = statusOfEachCode();
  return declaredCodes().filter((code) => (statuses.get(code) ?? 0) >= 500);
}

interface RefusalRow {
  /** The codes the row names, usually one. */
  readonly codes: string[];
  readonly status: number;
}

/** The refusal table's rows, as code names and the status written beside them. */
function refusalRows(): RefusalRow[] {
  return tableRows(documentText(), REFUSAL_TABLE).map((cells) => ({
    codes: [...(cells[1] ?? '').matchAll(/`([A-Z][A-Z0-9_]+)`/gu)].map((found) => found[1]!),
    status: Number(cells[2]),
  }));
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

  it('says that a check ahead of the credential file applies to every request whoever it names', () => {
    // The request bound sits before the file is read on one condition, and the document states it:
    // the check is uniform, so what it answers is a fact about the deployment and never about who is
    // in the file. Without this pinned, a rewrite of the section can drop the rule and leave a later
    // change moving a name-dependent check ahead of the lookup with nothing in the contract to
    // contradict it, which is the enumeration oracle the whole ordering exists to keep out.
    const rule =
      'every request meets it, whoever it names and whatever its header says, so the answer is a ' +
      'statement about this deployment and never about the file';
    // Read as one boolean rather than a `toContain` because the document is long enough that
    // echoing it back on a failure buries the sentence that went missing.
    const prose = documentText().replace(/\s+/gu, ' ');
    expect(prose.includes(rule), `section 1 states the uniformity the placement rests on: ${rule}`).toBe(true);
  });
});

describe('the refusal tables against gateway/src/access.ts', () => {
  it('keeps one list across the declared codes, the statuses and the sentences', () => {
    const codes = [...declaredCodes()].sort();
    const statuses = statusOfEachCode();
    expect([...statuses.keys()].sort(), 'the status map against the declared codes').toEqual(codes);
    expect(
      literalEntries('ERROR_MESSAGE', ACCESS_SOURCE).map((entry) => entry.key).sort(),
      'the message map against the declared codes',
    ).toEqual(codes);
    for (const [code, status] of statuses) {
      // A row this reader could not parse reads as `undefined` or `NaN`, which then fails against a
      // document that is telling the truth. Saying so here points at the declaration instead.
      expect(Number.isInteger(status), `${code} is answered with a whole status`).toBe(true);
    }
  });

  it('carries exactly one refusal row for every code the access layer declares', () => {
    const listed = refusalRows().flatMap((row) => row.codes);
    expect(new Set(listed).size, 'a code refused by more than one row').toBe(listed.length);
    expect([...listed].sort(), 'the refusal table against the declared codes').toEqual(
      [...declaredCodes()].sort(),
    );
  });

  it('answers each refusal with the status the mapping gives it', () => {
    const statuses = statusOfEachCode();
    const singles = refusalRows().filter((row) => row.codes.length === 1);
    expect(singles, 'the rows that stand one code each').toHaveLength(declaredCodes().length - codesNoRequestMeets().length);
    for (const row of singles) {
      const code = row.codes[0] ?? '';
      expect(`${code} -> ${row.status}`, 'the row and the map answer the same way').toBe(
        `${code} -> ${String(statuses.get(code))}`,
      );
    }
  });

  it('leaves the codes no request is answered with to one row, since the map answers them alike', () => {
    // Three of the codes are what the store says about a file rather than what a request meets, so
    // the table gives them a shared row instead of three caller-facing ones. The exception is
    // licensed by the mapping itself - every code on that row answers with the same status, and
    // they are exactly the codes the map answers as a server fault - and it is checked both ways: a
    // fourth code folding into the row, or one of them splitting out, fails here.
    const statuses = statusOfEachCode();
    const grouped = refusalRows().filter((row) => row.codes.length > 1);
    expect(grouped, 'the table groups the codes a request never meets into one row').toHaveLength(1);
    const row = grouped[0] ?? { codes: [], status: Number.NaN };
    const fileCodes = codesNoRequestMeets();
    expect([...row.codes].sort(), 'the codes on the grouped row').toEqual([...fileCodes].sort());
    expect(new Set(fileCodes.map((code) => statuses.get(code))).size, 'one status covers that whole row').toBe(1);
    expect(row.status, 'the grouped row states that status').toBe(statuses.get(fileCodes[0] ?? ''));
  });

  it('states the same statuses in docs/error-codes.md, and which codes each belongs to', () => {
    const prose = sectionBody(readSourceFile(CODES_DOC), ACCESS_SECTION).replace(/\s+/gu, ' ');
    // That table has no status column, so everything the reference says about the answers is in one
    // sentence: which statuses a request can be given, how many codes sit outside that, and what
    // those are answered with. Read it as data, because a claim no test can parse is a claim a
    // rewrite can quietly drop.
    const claim =
      /Codes after the (\w+) (\w+) are ([\d,\s or]+?) on the request that earned them; the credential-file codes are (\d+)/u.exec(
        prose,
      );
    expect(claim, 'the section says which statuses a request meets and which it never does').not.toBeNull();
    const [, ordinal, count, requestList, fileStatus] = claim ?? [];
    expect(ordinal, 'the sentence counts from the front of its own table').toBe('first');
    const fileCodes = codesNoRequestMeets();
    expect(spelledNumber(count ?? ''), 'how many codes the sentence sets apart').toBe(fileCodes.length);
    expect(declaredCodes().slice(0, fileCodes.length), 'those are the codes declared first').toEqual(fileCodes);
    const statuses = statusOfEachCode();
    expect(
      [...(requestList ?? '').matchAll(/\d{3}/gu)].map((found) => Number(found[0])).sort((a, b) => a - b),
      'the statuses the sentence lists for a request',
    ).toEqual(
      [
        ...new Set(
          declaredCodes()
            .filter((code) => !fileCodes.includes(code))
            .map((code) => statuses.get(code) ?? Number.NaN),
        ),
      ].sort((a, b) => a - b),
    );
    for (const code of fileCodes) {
      expect(Number(fileStatus), `${code} is answered with the status the sentence gives the file`).toBe(
        statuses.get(code),
      );
    }
  });

  it('rows the codes no request meets ahead of the rest in docs/error-codes.md', () => {
    // The count in the sentence above only points at those codes because of where the table puts
    // them, so the order of the rows is part of what the reference claims rather than a layout.
    const rows = tableRows(sectionBody(readSourceFile(CODES_DOC), ACCESS_SECTION), CODE_TABLE);
    const fileCodes = codesNoRequestMeets();
    expect(
      rows.slice(0, fileCodes.length).map((cells) => cells[1]?.replace(/`/gu, '') ?? ''),
      'the rows the section counts first',
    ).toEqual(fileCodes);
  });
});
