import { describe, expect, it } from 'vitest';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readSourceFile, spelledNumber } from './doc-contract.js';

/**
 * The receipt payload has one version. `packages/receipt/receipt.cddl` declares it, and
 * `packages/receipt/src/receipt.ts` writes the set of versions its reader parses in one place, the list
 * `PARSED_VERSIONS`, which is what the exported `isReceiptVersion` answers from and what `ACCEPTED_BY_DEFAULT` is
 * read off rather than restated.
 *
 * A published document naming a second payload version is not a typo to be fixed once: it is a promise a
 * reimplementer can be held to and that no reader here keeps, and a promise no test reads is a promise
 * nothing holds. So this file reads them.
 *
 * The version set is taken from the receipt package and the claims from the documents, and neither is written
 * twice here. The set is read out of the one declaration that holds it rather than imported, because
 * `isReceiptVersion` is deliberately kept off the package's index and a cross-package source import does not sit
 * inside this package's `rootDir`. A claim is refused when it names a number outside the set, and a claim that
 * counts the versions is refused when the count is not the size of the set, which is the same fact pointed at a
 * sentence that names no number at all.
 *
 * Which family a paragraph belongs to is resolved from the section carrying it, because several families of this
 * estate really do carry more than one version, or carry one number that is not the payload's: the retention
 * manifest keeps two layouts, the deployment manifest is a document whose `v` moves for reasons of its own, and
 * every container spec says "payload" about its own signed body. Those sentences are read as theirs. The case
 * below that asks what every `v: 2` in these files belongs to is the guard that keeps that reading from being done
 * by a sweep which treats any number in the neighbourhood of a receipt as a payload claim.
 *
 * What this reaches, stated as a limit rather than as a claim of completeness: a payload version spelled `v: N`
 * with a receipt or payload word inside the window around it, a number in backticks inside a sentence that says
 * "payload version" or "receipt version" or "receipt format version", and a count of versions spelled before the
 * word ("one payload version", "three receipt versions") or as the set a sentence points back at ("of the three").
 * It does not reach "version two" spelled after the word, which is how the retention layouts name themselves and
 * is the spelling this sweep must not be tempted to refuse; it does not reach a paragraph that opens on another
 * container and buries a payload claim behind it; and it does not reach a sentence that describes a retired number
 * without naming one.
 */

const RECEIPT_SRC = '../../receipt/src/receipt.ts';
const DOC_DIR = '../../../docs';
const README = '../../../README.md';

/** How close, in characters, a receipt or payload word has to sit to a number for the pair to be one claim. */
const WINDOW = 48;

/** The payload set this package reads, and nothing else is asked of the documents. */
const RECEIPT_VERSIONS = declaredVersions('PARSED_VERSIONS', RECEIPT_SRC);

/** The families whose version numbers are their own, wherever one of them is met. */
const OTHER_FAMILIES: readonly (readonly [marker: RegExp, family: string])[] = [
  [/retention manifest/iu, 'retention manifest'],
  [/deployment manifest/iu, 'deployment manifest'],
  [/pack manifest/iu, 'pack manifest'],
  [/export manifest/iu, 'export manifest'],
  [/redaction manifest/iu, 'redaction manifest'],
  [/epoch inventory/iu, 'epoch inventory'],
  [/capture record/iu, 'capture record'],
  [/verification polic(?:y|ies)/iu, 'verification policy'],
];

/** The payload family too, which is what a paragraph is read against when it names a document at all. */
const FAMILIES: readonly (readonly [marker: RegExp, string])[] = [
  ...OTHER_FAMILIES,
  [/\b(?:receipt|receipts|payload|payloads)\b/iu, 'payload'],
];

/** The family a document speaks of throughout, read out of the title it opens with. */
const TITLE_FAMILIES: readonly (readonly [marker: RegExp, family: string])[] = [
  [/evidence pack/iu, 'pack manifest'],
  [/technical export/iu, 'export manifest'],
  [/epoch inventory/iu, 'epoch inventory'],
  [/capture record/iu, 'capture record'],
  [/receipt specification/iu, 'payload'],
];

const PAYLOAD_WORD = /\b(?:receipt|receipts|payload|payloads)\b/iu;
const RECEIPT_WORD = /\breceipts?\b/iu;
const VERSION_WORD = /\bversions?\b/iu;
const NUMBER_WORDS =
  '(?:[0-9]+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)';

interface Claim {
  readonly file: string;
  readonly line: number;
  readonly number: number;
  /** Whether the sentence names one version or counts them, which are two different questions to ask of a set. */
  readonly kind: 'names' | 'counts';
  /** Which spelling carried the claim, so a refusal points at the sentence rather than at a bare figure. */
  readonly spelled: string;
}

/** The members of a `const <name> = [ ... ];` declaration, read as the numbers the source writes. */
function declaredVersions(name: string, file: string): number[] {
  const source = readSourceFile(file);
  const declared = new RegExp(`const ${name}(?::[^=]+)? = \\[([^\\]]*)\\]`, 'u').exec(source);
  if (declared === null) throw new Error(`${name} is not a bracketed list this reader can find in ${file}`);
  const cells = (declared[1] ?? '')
    .split(',')
    .map((cell) => cell.trim())
    .filter((cell) => cell.length > 0);
  if (cells.length === 0) throw new Error(`${name} in ${file} declares no versions, so there is nothing to hold a document to`);
  return cells.map((cell) => {
    if (!/^[0-9]+$/u.test(cell)) throw new Error(`${name} in ${file} carries ${cell}, which is not a version number`);
    return Number(cell);
  });
}

/** A number spelled the way a document spells one, which is the word list the framing tests already read. */
function counted(spelled: string): number {
  return /^[0-9]+$/u.test(spelled) ? Number(spelled) : spelledNumber(spelled);
}

/** Every published markdown file the sweep reads: the documents directory and the front page. */
function publishedDocuments(): string[] {
  const names = readdirSync(fileURLToPath(new URL(DOC_DIR, import.meta.url)))
    .filter((name) => name.endsWith('.md'))
    .sort();
  expect(names.length, 'the documents directory yielded nothing to read').toBeGreaterThanOrEqual(8);
  return [...names.map((name) => `${DOC_DIR}/${name}`), README];
}

interface Block {
  readonly file: string;
  readonly line: number;
  /** The nearest heading above the block, which is the section carrying it. */
  readonly heading: string;
  /** The `# ` line the document opens with, which carries every section in it. */
  readonly title: string;
  readonly text: string;
}

/**
 * The document in blocks of prose that each carry one family: a run of wrapped lines, or a single table row, with
 * the heading above it and the line it began on.
 *
 * A table row is a block of its own because one row is one statement in these documents, and joining a table into
 * one paragraph would let the first row's subject speak for the rows behind it.
 */
function blocksOf(file: string, markdown: string): Block[] {
  const lines = markdown.split('\n');
  const out: Block[] = [];
  let heading = '';
  let title = '';
  let buffer: string[] = [];
  let start = 0;
  const flush = (): void => {
    if (buffer.length === 0) return;
    out.push({ file, line: start, heading, title, text: buffer.join(' ').replace(/\s+/gu, ' ') });
    buffer = [];
  };
  lines.forEach((line, at) => {
    if (/^#{1,6} /u.test(line)) {
      flush();
      heading = line;
      if (title.length === 0) title = line;
      return;
    }
    if (line.trim().length === 0) {
      flush();
      return;
    }
    if (line.startsWith('|')) {
      flush();
      out.push({ file, line: at + 1, heading, title, text: line.replace(/\s+/gu, ' ') });
      return;
    }
    if (buffer.length === 0) start = at + 1;
    buffer.push(line);
  });
  flush();
  return out;
}

/** Sentences, split where a full stop is followed by a capital or an opening backtick. */
function sentencesOf(text: string): string[] {
  return text
    .split(/(?<=[.!?])\s+(?=[A-Z`])/u)
    .map((sentence) => sentence.trim())
    .filter((sentence) => sentence.length > 0);
}

/** The family a piece of text names first, or null where it names none of that table's. */
function firstFamily(text: string, table: readonly (readonly [RegExp, string])[]): string | null {
  let best = -1;
  let family: string | null = null;
  for (const [marker, name] of table) {
    const found = text.search(marker);
    if (found >= 0 && (best < 0 || found < best)) {
      best = found;
      family = name;
    }
  }
  return family;
}

/**
 * The family a block belongs to: the carrying section if it names one, then the family the block opens on, then
 * the title of the document. A block that rests on the bare word "payload" and never names a receipt is a
 * container talking about its own signed body, and the title is what says which container, because each of these
 * formats spells its payload `v: 1` and none of those numbers is the payload's.
 */
function familyOf(block: Block): string {
  const section = firstFamily(block.heading, OTHER_FAMILIES);
  if (section !== null) return section;
  const opened = firstFamily(block.text, FAMILIES);
  if (opened === 'payload' && !RECEIPT_WORD.test(block.text)) {
    return firstFamily(block.title, TITLE_FAMILIES) ?? 'payload';
  }
  return opened ?? firstFamily(block.title, TITLE_FAMILIES) ?? 'unmarked';
}

/** A number is claimed by the payload only when a receipt or payload word sits inside the window around it. */
function besidePayload(text: string, at: number, length: number): boolean {
  return (
    PAYLOAD_WORD.test(text.slice(Math.max(0, at - WINDOW), at)) ||
    PAYLOAD_WORD.test(text.slice(Math.min(text.length, at + length), at + length + WINDOW))
  );
}

function claimsOf(block: Block): Claim[] {
  if (familyOf(block) !== 'payload') return [];
  const out: Claim[] = [];
  const add = (kind: Claim['kind'], number: number, spelled: string): void => {
    out.push({ file: block.file, line: block.line, number, kind, spelled });
  };
  for (const sentence of sentencesOf(block.text)) {
    // A version spelled the way the payload spells its own member, read only when a receipt word sits beside it.
    for (const found of sentence.matchAll(/`v:\s*([0-9]+)`/gu)) {
      if (besidePayload(sentence, found.index, found[0].length)) add('names', Number(found[1]), found[0]);
    }
    // Every number in backticks inside a sentence that says which family it is naming versions for.
    if (/\b(?:payload|receipt)(?:[ -]format)?[ -]versions?\b/iu.test(sentence)) {
      for (const found of sentence.matchAll(/`([0-9]+)`/gu)) add('names', Number(found[1]), found[0]);
    }
    // A count of the versions, spelled before the word or as the set the sentence points back at.
    for (const found of sentence.matchAll(new RegExp(`\\b(${NUMBER_WORDS}) (?:payload |receipt )?versions?\\b`, 'giu'))) {
      add('counts', counted(found[1] ?? ''), found[0]);
    }
    for (const found of sentence.matchAll(new RegExp(`\\bof the (${NUMBER_WORDS})\\b`, 'giu'))) {
      if (VERSION_WORD.test(sentence.slice(Math.max(0, found.index - WINDOW), found.index))) {
        add('counts', counted(found[1] ?? ''), found[0]);
      }
    }
  }
  return out;
}

const claims = publishedDocuments().flatMap((file) => blocksOf(file, readSourceFile(file)).flatMap(claimsOf));

/** The sentences naming a version this package does not read. */
const unreadable = claims.filter((claim) => claim.kind === 'names' && !RECEIPT_VERSIONS.includes(claim.number));
/** The sentences counting the versions at a number other than the size of the set. */
const miscounted = claims.filter((claim) => claim.kind === 'counts' && claim.number !== RECEIPT_VERSIONS.length);

/** The blocks spelling `v: 2`, and the family each is read under. */
const versionTwo = publishedDocuments().flatMap((file) =>
  blocksOf(file, readSourceFile(file))
    .filter((block) => /`v: 2`/u.test(block.text))
    .map((block) => ({ block, family: familyOf(block) })),
);

/** A refusal that quotes its sentence rather than a figure the reader has to go and find. */
function describeClaim(claim: Claim): string {
  const line = readSourceFile(claim.file).split('\n')[claim.line - 1] ?? '';
  return `${claim.file.slice(claim.file.lastIndexOf('/') + 1)}:${String(claim.line)} spells ${claim.spelled} in "${line.slice(0, 88)}"`;
}

describe('published documents state one receipt payload version', () => {
  it('reads the version set from the one declaration the reader is written over', () => {
    const source = readSourceFile(RECEIPT_SRC);
    expect(RECEIPT_VERSIONS.length, 'the set is written in the package, and this reads it rather than restating it').toBeGreaterThanOrEqual(1);
    // The exported predicate answers out of that list and the default accepted set is that list, so the three
    // statements cannot drift apart: a second copy of the set is the disagreement this case is written for.
    expect(
      /export function isReceiptVersion[\s\S]{0,220}PARSED_VERSIONS/u.test(source),
      'isReceiptVersion no longer answers from the list this reads',
    ).toBe(true);
    expect(
      /const ACCEPTED_BY_DEFAULT\b[^;\n]*=\s*PARSED_VERSIONS/u.test(source),
      'the default accepted set is no longer the list this reads',
    ).toBe(true);
    expect(RECEIPT_VERSIONS, 'a version is named twice in the list that holds the set').toEqual([...new Set(RECEIPT_VERSIONS)]);
  });

  it('names no receipt payload version the package does not read', () => {
    expect(unreadable.map(describeClaim), 'the documents claim payload versions the reader does not parse').toEqual([]);
  });

  it('counts the payload versions at the number the reader parses', () => {
    expect(miscounted.map(describeClaim), 'a sentence counts payload versions and the count is not the size of the set').toEqual([]);
  });

  it('reads a sentence of another family as the family that owns it', () => {
    // Every `v: 2` in the published documents belongs to the retention layouts or to the deployment manifest, and
    // none of them is a payload claim. Refusing these would trade two true sentences for a false nobody wrote.
    expect(versionTwo.length, 'this found no `v: 2` to classify, so it is guarding nothing').toBeGreaterThanOrEqual(2);
    expect(
      versionTwo.filter((one) => one.family === 'payload').map((one) => `${one.block.file.split('/').pop()}:${String(one.block.line)}`),
      'a `v: 2` sentence is being read as a receipt payload claim',
    ).toEqual([]);
    expect([...new Set(versionTwo.map((one) => one.family))].sort(), 'the `v: 2` sentences are not read as the families that own them').toEqual([
      'deployment manifest',
      'retention manifest',
    ]);
  });

  it('reads the documents it is pointed at and reaches the claims they carry', () => {
    const files = new Set(claims.map((claim) => claim.file.slice(claim.file.lastIndexOf('/') + 1)));
    expect([...files].sort(), 'the claims read come from too few of the published documents').toEqual(
      expect.arrayContaining(['capture-v1.md', 'receipt-spec.md']),
    );
    expect(claims.length, 'the sweep reached almost no version claim, so it is matching nothing').toBeGreaterThanOrEqual(8);
    expect(
      claims.filter((claim) => claim.file.endsWith('capture-v1.md')).length,
      'the capture document stopped making payload version claims this can read',
    ).toBeGreaterThanOrEqual(3);
  });
});
