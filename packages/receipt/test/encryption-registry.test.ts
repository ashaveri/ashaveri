import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ENCRYPTION_SCHEMES } from '../src/index.js';

/**
 * Section 3.4 of `docs/receipt-spec.md` is the half of the encryption rule a stranger reads, so it is
 * tested rather than admired. The list this package parses and the table the document publishes are one
 * registry written twice on purpose, and the only way either of them goes stale quietly is that no reader
 * compares the two: a row the parser does not accept tells a verifier to weigh bytes under a construction
 * no receipt can produce, and a label the parser accepts that the table never names is a claim a document
 * makes about its own bytes that no published rule describes.
 */

/** The specification whose section 3.4 publishes the rows this package parses. */
const SPEC_PATH = fileURLToPath(new URL('../../../docs/receipt-spec.md', import.meta.url));

/**
 * One section of the specification, from its heading to the next heading at either level: the body a
 * reader of that section actually gets, and nothing a neighbouring section says about a different member.
 */
function sectionBody(heading: string): string {
  const lines = readFileSync(SPEC_PATH, 'utf8').split('\n');
  const start = lines.indexOf(heading);
  if (start < 0) throw new Error(`${heading} is not a heading in ${SPEC_PATH}`);
  const rest = lines.slice(start + 1);
  const constEnd = rest.findIndex((line) => line.startsWith('## ') || line.startsWith('### '));
  return (constEnd < 0 ? rest : rest.slice(0, constEnd)).join('\n');
}

const SECTION = '### 3.4 Encryption schemes';

describe('the published encryption registry', () => {
  it('is a numbered section 3.4, which is what the code cites', () => {
    expect(sectionBody(SECTION)).toContain('`enc.sch`');
  });

  it('lists exactly the schemes this package parses, in the order it declares them', () => {
    const listed = sectionBody(SECTION)
      .split('\n')
      .map((line) => /^\| `"([a-z0-9-]+)"` \|/u.exec(line)?.[1])
      .filter((label): label is string => label !== undefined);
    expect(listed, 'the labels section 3.4 publishes').toEqual([...ENCRYPTION_SCHEMES]);
  });

  it('refuses a row for a label this package cannot interpret, in either direction', () => {
    // A row that vanished would leave the table short of a construction the parser still accepts, and the
    // reader of the table would be the last to know. The two sentences are one test rather than two because
    // both are the same question asked of the same pair, and only the direction differs.
    const published = new Set(
      sectionBody(SECTION)
        .split('\n')
        .map((line) => /^\| `"([a-z0-9-]+)"` \|/u.exec(line)?.[1])
        .filter((label): label is string => label !== undefined),
    );
    for (const scheme of ENCRYPTION_SCHEMES) {
      expect(published.has(scheme), `the parser accepts ${scheme} and the table names it`).toBe(true);
    }
    for (const label of published) {
      expect((ENCRYPTION_SCHEMES as readonly string[]).includes(label), `the table names ${label} and the parser accepts it`).toBe(true);
    }
  });

  it('names the refusal an unknown label answers, and which registry that refusal belongs to', () => {
    const body = sectionBody(SECTION).replace(/\s+/gu, ' ');
    expect(body).toContain('`UNSUPPORTED_ENCRYPTION_SCHEME`');
    // The two registries keep their own codes, and the section has to say so: a reader that was pointed at
    // the marking answer would look for a mark's absence where the document states a cipher it cannot read.
    expect(body).toContain('`UNSUPPORTED_SCHEME`');
    expect(body).toContain('`BAD_PAYLOAD`');
  });

  it('states what each arm carries, because the label is what closes the map', () => {
    const body = sectionBody(SECTION).replace(/\s+/gu, ' ');
    expect(body).toContain('`pk`');
    expect(body).toContain('32-byte');
    expect(body).toContain('no single list answers for both');
  });

  it('says what the receipt leaves unproved about the key it names', () => {
    // This is the sentence a reader would otherwise fill in with a claim: that a session document proves
    // its key came from the measurement it attests. It does not, and the section that publishes the label
    // is where the absence has to be stated rather than inferred from silence.
    const body = sectionBody(SECTION).replace(/\s+/gu, ' ');
    expect(body).toContain('report data');
    expect(body).toContain('second document');
  });
});
