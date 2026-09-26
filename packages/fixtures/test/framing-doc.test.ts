import { describe, expect, it } from 'vitest';
import { fromBase64Url } from '@ashaveri/receipt';
import { loadChainVectors, type ChainRecord, type ChainVectorFile } from '../src/index.js';
import { readSourceFile, sectionBody, tableRows } from './doc-contract.js';

/**
 * The framing prose in `docs/receipt-spec.md` and the record format in `data/chain-v1.json` state the
 * same bytes in two media, which is how one comes to disagree with the other. This reads the section as
 * data (its field tables, its kind values, the layout strings it quotes) and checks every byte
 * position against the vector file's published records, so a rewrite that drops a field or moves an
 * offset fails here rather than teaching a reader a framing no store writes.
 *
 * The offsets are validated against concrete records lifted out of the vectors, not against numbers
 * typed in here: a fixed field's position is the running sum of the widths the vector's `layout.record`
 * states, and the variable `id` and `payload` positions follow from a real record's published length
 * and id. That is the whole of the anti-drift property the section claims: the prose cannot state an
 * offset the bytes it describes do not carry.
 */

const DOC = '../../../docs/receipt-spec.md';
/** The one subsection this test reads, matched by its full heading line. */
const SECTION = '### 5.2 Record framing and chain recomputation';
/** Header of the frame-layout table: one row per field of a record frame. */
const FRAME_TABLE = '| Field | Byte offset in one frame | Width |';
/** Header of the trim-payload table: one row per field inside a trim record's payload. */
const TRIM_TABLE = '| Field | Byte offset in the trim payload | Width |';
/** Header of the kind-value table: one row per `kind` byte value the layout defines. */
const KIND_TABLE = '| Record kind | Byte value |';
/** The scenario whose first record the frame table is spelled against; named so a reorder is visible. */
const FRAME_SCENARIO = 'first-record';

const file: ChainVectorFile = loadChainVectors();

/** Widths the layout spells for an integer field; `:NN` is a fixed NN-byte blob. */
function widthOf(spec: string | undefined): number | undefined {
  switch (spec) {
    case 'u8':
      return 1;
    case 'u16':
      return 2;
    case 'u32':
      return 4;
    case 'u64':
      return 8;
    default: {
      if (spec === undefined || spec === '') return undefined;
      const fixed = Number(spec);
      return Number.isInteger(fixed) && fixed > 0 ? fixed : undefined;
    }
  }
}

/** The ordered field names and declared widths parsed out of a `name:width || ...` layout string. */
function layoutFields(layout: string): { name: string; width: number | undefined }[] {
  return layout.split('||').map((token) => {
    const [name = '', spec = ''] = token.trim().split(':').map((each) => each.trim());
    return { name, width: widthOf(spec) };
  });
}

/**
 * The frame offsets the vector's layout and one concrete record imply, in field order. The variable
 * fields are resolved against `record`'s published id and length, so the numbers checked below come out
 * of the bytes, not out of a transcription of them.
 */
function expectedFrameOffsets(record: ChainRecord): Map<string, { start: number; width: number }> {
  const out = new Map<string, { start: number; width: number }>();
  const digest = widthOf('32') ?? 32;
  const idWidth = Buffer.byteLength(record.id, 'utf8');
  // `len` counts kind through digest, so the payload width is what is left of `len` after the fixed
  // header, the id and the digest have taken their share.
  const fixedHeader = layoutFields(file.layout.record)
    .filter(({ name, width }) => width !== undefined && name !== 'len' && name !== 'digest')
    .reduce((sum, { width }) => sum + (width ?? 0), 0);
  const payloadWidth = record.length - digest - fixedHeader - idWidth;
  const varWidth: Record<string, number> = { id: idWidth, payload: payloadWidth };
  let cursor = 0;
  for (const { name, width } of layoutFields(file.layout.record)) {
    const resolved = width ?? varWidth[name];
    if (resolved === undefined) throw new Error(`layout field ${name} has neither a declared width nor a value in the record`);
    out.set(name, { start: cursor, width: resolved });
    cursor += resolved;
  }
  return out;
}

/** The trim-payload offsets the vector's `trimPayload` layout implies, counting from its first byte. */
function expectedTrimOffsets(): Map<string, { start: number; width: number }> {
  const out = new Map<string, { start: number; width: number }>();
  let cursor = 0;
  for (const { name, width } of layoutFields(file.layout.trimPayload)) {
    if (width === undefined) throw new Error(`trim field ${name} states no width`);
    out.set(name, { start: cursor, width });
    cursor += width;
  }
  return out;
}

interface Row {
  readonly name: string;
  readonly start: number;
  readonly end: number;
  readonly width: number;
}

/**
 * A layout table's rows as field name, inclusive byte range and width. A row spells its range as
 * `a-b`; the width beside it is checked against that range in the test body rather than trusted here,
 * because a table whose offset and width columns disagree is itself a drift the reader inherits.
 */
function readOffsetsTable(body: string, header: string): Row[] {
  return tableRows(body, header).map((cells) => {
    const name = cells[1]?.replace(/`/gu, '').trim() ?? '';
    const range = /(\d+)-(\d+)/u.exec(cells[2] ?? '');
    if (!range) throw new Error(`row for ${name} states no \`a-b\` byte range`);
    return { name, start: Number(range[1]), end: Number(range[2]), width: Number(cells[3]) };
  });
}

function recordNamed(scenario: string): ChainRecord {
  const found = file.scenarios.find((each) => each.name === scenario) ?? file.scenarios[0];
  if (found === undefined || found.records[0] === undefined) {
    throw new Error(`data/chain-v1.json has no scenario ${scenario} to read the frame table against`);
  }
  return found.records[0];
}

function firstTrimRecord(): ChainRecord {
  for (const scenario of file.scenarios) {
    const trim = scenario.records.find((record) => record.kind === file.layout.kinds.trim);
    if (trim !== undefined) return trim;
  }
  throw new Error('no scenario holds a trim record to read the trim table against');
}

function section(): string {
  return sectionBody(readSourceFile(DOC), SECTION);
}

describe('docs/receipt-spec.md record framing (5.2)', () => {
  it('quotes the frame and trim layouts the vector states, and names the file it lays out', () => {
    const body = section();
    // The fenced layout strings are the vector's own, so a rewrite that restates them in other words
    // still has to carry the same tokens or it will not be a quotation of them.
    expect(body).toContain(file.layout.record);
    expect(body).toContain(file.layout.trimPayload);
    expect(body).toContain(file.layout.file);
    for (const word of file.layout.integers.split(',').map((each) => each.trim())) {
      expect(body, `the section states integers are ${word}`).toContain(word);
    }
  });

  it('names every field the record layout in the vector carries', () => {
    const rows = new Map(readOffsetsTable(section(), FRAME_TABLE).map((row) => [row.name, row]));
    for (const { name } of layoutFields(file.layout.record)) {
      expect(rows.has(name), `the frame table omits the layout field ${name}`).toBe(true);
    }
  });

  it('states frame offsets the published bytes do not contradict', () => {
    const record = recordNamed(FRAME_SCENARIO);
    const expected = expectedFrameOffsets(record);
    const rows = readOffsetsTable(section(), FRAME_TABLE);
    for (const row of rows) {
      const want = expected.get(row.name);
      expect(want, `the frame table names ${row.name}, which the vector's layout does not`).toBeDefined();
      if (want === undefined) continue;
      expect(row.start, `${row.name} starts at the offset the layout implies`).toBe(want.start);
      expect(row.width, `${row.name} is as wide as the layout states`).toBe(want.width);
      expect(row.end, `${row.name}'s range agrees with its own start and width`).toBe(row.start + row.width - 1);
    }
    // The digest is the frame's tail, so its published offset has to meet the frame length the record
    // states, and the fixed widths themselves have to match the hex fields on the record.
    const digest = rows.find((row) => row.name === 'digest');
    expect(digest?.start, 'digest sits at the end of the frame').toBe(record.frameByteLength - (digest?.width ?? 0));
    expect(record.prevHex.length / 2, 'prev width matches the predecessor hex').toBe(expected.get('prev')?.width);
    expect(record.digestHex.length / 2, 'digest width matches the published digest hex').toBe(expected.get('digest')?.width);
  });

  it('hashes less than the frame it sits in, by the gap the layout states', () => {
    const record = recordNamed(FRAME_SCENARIO);
    const rows = new Map(readOffsetsTable(section(), FRAME_TABLE).map((row) => [row.name, row]));
    const kind = rows.get('kind');
    const payload = rows.get('payload');
    const len = rows.get('len');
    const digest = rows.get('digest');
    expect(kind && payload && len && digest, 'the frame table names kind, payload, len and digest').toBeTruthy();
    if (kind === undefined || payload === undefined || len === undefined || digest === undefined) return;
    // The digest input runs from the first byte of `kind` to the last byte of `payload`; the hashed span
    // has to be `len` minus the digest and narrower than the frame by the length prefix too.
    const hashedWidth = payload.end - kind.start + 1;
    expect(hashedWidth, 'digest input is kind through payload, that is len minus the digest').toBe(
      record.length - digest.width,
    );
    expect(hashedWidth, 'the digest input is narrower than the frame').toBeLessThan(record.frameByteLength);
    expect(record.frameByteLength - hashedWidth, 'the gap is the length prefix and the digest').toBe(
      len.width + digest.width,
    );
  });

  it('names every field the trim-payload layout in the vector carries', () => {
    const rows = new Map(readOffsetsTable(section(), TRIM_TABLE).map((row) => [row.name, row]));
    for (const { name } of layoutFields(file.layout.trimPayload)) {
      expect(rows.has(name), `the trim table omits the payload field ${name}`).toBe(true);
    }
  });

  it('states trim offsets the published bytes do not contradict', () => {
    const trim = firstTrimRecord();
    const expected = expectedTrimOffsets();
    const rows = readOffsetsTable(section(), TRIM_TABLE);
    let span = 0;
    for (const row of rows) {
      const want = expected.get(row.name);
      expect(want, `the trim table names ${row.name}, which the vector's trim layout does not`).toBeDefined();
      if (want === undefined) continue;
      expect(row.start, `${row.name} starts where the widths before it end`).toBe(want.start);
      expect(row.width, `${row.name} is as wide as its declared integer or blob`).toBe(want.width);
      expect(row.end, `${row.name}'s range agrees with its own start and width`).toBe(row.start + row.width - 1);
      span += row.width;
    }
    expect(span, 'the trim fields fill the payload the record carries').toBe(
      fromBase64Url(trim.payloadBase64Url).length,
    );
  });

  it('gives the two kind values the vector defines, and no other', () => {
    const rows = tableRows(section(), KIND_TABLE).map((cells) => ({
      name: cells[1]?.replace(/`/gu, '').trim() ?? '',
      value: Number(cells[2]),
    }));
    const stated = Object.fromEntries(rows.map((row) => [row.name, row.value]));
    expect(stated, 'the kind table states the same values the layout gives').toEqual(file.layout.kinds);
  });

  it('tells the reader to reproduce every refusal the vector publishes', () => {
    const body = section();
    expect(file.refusals.length, 'the vector publishes at least one refusal').toBeGreaterThan(0);
    for (const refusal of file.refusals) {
      expect(body, `the section names the ${refusal.name} refusal a reader must reproduce`).toContain(refusal.name);
      expect(body, `the section names the code ${refusal.name} raises`).toContain(refusal.code);
    }
  });
});
