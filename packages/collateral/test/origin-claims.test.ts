import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import {
  DECLARED_ORIGINS,
  ORIGIN_DECLARATIONS,
  SERVED_ORIGINS,
  collateralRefusals,
  type CollateralOriginName,
  type ReadCollateralOrigin,
} from '../src/index.js';
import * as barrel from '../src/index.js';

/**
 * The names-and-counts gate over the origin prose of three documents.
 *
 * A sentence about which origins are read is a claim about a list, and a list changes in code without changing
 * the sentence beside it. This suite reads `docs/error-codes.md`, `docs/threat-model.md` and `README.md` and
 * holds what they say about origins to `DECLARED_ORIGINS` and `SERVED_ORIGINS`: a name the prose cites as an
 * origin is one the package declares, an enumeration of the read origins is exactly the ones it reads, an
 * enumeration of the refused ones exactly the remainder, and a count stated beside those sentences is the
 * length of the list it counts. Entry points the prose names are checked against the package's exports, so a
 * rename lands here rather than in a document a caller trusts. The claim that no shipped command asks an origin
 * is read out of the sources of the shipped commands rather than out of the prose that states it.
 *
 * What stays a reader's work is the argument inside a sentence, and the vocabulary below names the backticked
 * words that are material facts rather than symbols of this package.
 */

const ERROR_CODES = 'docs/error-codes.md';
const THREAT_MODEL = 'docs/threat-model.md';
const README = 'README.md';

const GRID_HEADING = '## Which origin can reach which refusal';
const KEEPING_HEADING = '## Keeping this file true';
const THREAT_MARKER = '- **No vendor attestation collateral is fetched by anything in this code.**';
const README_HEADING = '## Attestation collateral';

/**
 * The words the documents use for an origin beside its declared name. A sentence carrying one of these makes a
 * claim about that origin, which is what decides what the gate reads.
 */
const PROSE_ALIASES: Readonly<Record<CollateralOriginName, readonly string[]>> = {
  'intel-tcb-info': ['Intel TCB Info', 'TCB Info'],
  'intel-qe-identity': ['QE Identity', 'enclave identity'],
  'intel-pck-crl': ['PCK CRL'],
  'amd-kds': ['AMD KDS', 'KDS'],
  'nvidia-rim': ['NVIDIA RIM', 'RIM'],
  ocsp: ['NVIDIA OCSP', 'OCSP'],
};

/**
 * Backticked names in that prose which are not entry points: members a vendor document or a revocation entry
 * states, a query field, the state a revocation answer takes, and the words a grid cell answers with. Each is a
 * fact about material or about a cell rather than a symbol this package exports, so it is named rather than
 * guessed around.
 */
const DOCUMENTED_OTHER_NAMES = ['thisUpdate', 'nextUpdate', 'ca', 'removeFromCRL', 'not-listed', 'yes', 'no', 'false', 'strict'];

/** The sources a shipped command is built from, and the surface none of them may name outside a comment. */
const SHIPPED_SOURCES = ['packages/cli/src', 'packages/sdk/src', 'packages/receipt/src', 'gateway/src'];
const ORIGIN_ASKING_NAMES = [
  'fetchFromOrigin',
  'readServedCollateral',
  'requestUrl',
  'appraiseCollateral',
  'appraisePckCrl',
  'appraiseVcekChain',
];

const CODES = collateralRefusals().map((entry) => entry.code);
const UNREAD = DECLARED_ORIGINS.filter((name) => !SERVED_ORIGINS.includes(name as ReadCollateralOrigin));

const REPO = fileURLToPath(new URL('../../../', import.meta.url));

function documentOf(path: string): string {
  return readFileSync(join(REPO, path), 'utf8');
}

/** The body of a `## <heading>` section, up to the next heading of the same kind. */
function section(markdown: string, heading: string): string {
  const lines = markdown.split('\n');
  const start = lines.indexOf(heading);
  if (start < 0) {
    throw new Error(`${heading} is not a heading in the document`);
  }
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

/** The body of one `- **` bullet, which is where the collateral prose of the threat model sits. */
function bullet(markdown: string, marker: string): string {
  const lines = markdown.split('\n');
  const start = lines.findIndex((line) => line.startsWith(marker));
  if (start < 0) {
    throw new Error(`${marker.slice(0, 48)} is not a bullet in the document`);
  }
  const rest = lines.slice(start);
  const end = rest.findIndex((line, index) => index > 0 && line.startsWith('- **'));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

/**
 * The region as prose, one entry per sentence. Table rows are left out because the grid itself belongs to
 * `refusal-reachability.test.ts`, which reads its cells rather than its sentences.
 */
function sentences(text: string): string[] {
  const prose = text
    .split('\n')
    .filter((line) => !line.startsWith('|'))
    .join(' ')
    .replace(/\s+/gu, ' ')
    .trim();
  return prose.split(/(?<=[.!])\s+/u).filter((one) => one.length > 0);
}

function isOriginName(token: string): boolean {
  return DECLARED_ORIGINS.includes(token as CollateralOriginName);
}

function declaredNameMentioned(sentence: string): boolean {
  return DECLARED_ORIGINS.some((name) => sentence.includes(`\`${name}\``))
    || DECLARED_ORIGINS.some((name) => PROSE_ALIASES[name].some((alias) => sentence.includes(alias)))
    || sentence.includes('@ashaveri/collateral')
    || /\borigins?\b/u.test(sentence);
}

/** The declared origins a sentence names by its backticked canonical name. */
function namesInBackticks(sentence: string): CollateralOriginName[] {
  return DECLARED_ORIGINS.filter((name) => sentence.includes(`\`${name}\``));
}

function backticked(sentence: string): string[] {
  return [...sentence.matchAll(/`([^`]+)`/gu)].map((found) => found[1] as string);
}

/** A count a document states, spelled as digits or as a number word. */
const NUMBER_WORDS: Readonly<Record<string, number>> = {
  zero: 0,
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
  thirteen: 13,
  fourteen: 14,
};

function counted(spelling: string): number {
  const word = NUMBER_WORDS[spelling.toLowerCase()];
  if (word !== undefined) {
    return word;
  }
  if (/^\d+$/u.test(spelling)) {
    return Number(spelling);
  }
  throw new Error(`${spelling} is neither a digit nor a number word this estate writes`);
}

/**
 * The counts the documents state about origins, each beside the sentence that states it, and the list each count
 * is a fact about. A sentence that counts a list counts it as the package declares it or the run fails.
 */
const COUNT_CLAIMS: readonly (readonly [doc: string, claim: RegExp, counts: () => number[]])[] = [
  [
    ERROR_CODES,
    /the grid has (\w+) rows, one for each pair of the (\w+) origins named by `SERVED_ORIGINS` and the (\w+) members of `CollateralErrorCode`/iu,
    () => [SERVED_ORIGINS.length * CODES.length, SERVED_ORIGINS.length, CODES.length],
  ],
  [ERROR_CODES, /not one of the (\w+) cells reads `not exercised`/iu, () => [SERVED_ORIGINS.length * CODES.length]],
  [THREAT_MODEL, /declares (\w+) origins and reads (\w+)/iu, () => [DECLARED_ORIGINS.length, SERVED_ORIGINS.length]],
  [THREAT_MODEL, /declares the other (\w+)/iu, () => [UNREAD.length]],
  [README, /names (\w+) origins and reads (\w+)/iu, () => [DECLARED_ORIGINS.length, SERVED_ORIGINS.length]],
  [
    README,
    /the (\w+) intel json documents/iu,
    () => [Object.values(ORIGIN_DECLARATIONS).filter((one) => one.reader.as === 'served-json-document').length],
  ],
];

const REGIONS: ReadonlyMap<string, string> = new Map([
  [ERROR_CODES, `${section(documentOf(ERROR_CODES), GRID_HEADING)} ${section(documentOf(ERROR_CODES), KEEPING_HEADING)}`],
  [THREAT_MODEL, bullet(documentOf(THREAT_MODEL), THREAT_MARKER)],
  [README, section(documentOf(README), README_HEADING)],
]);

/** Every source file under a tracked directory, which is the text a shipped command is built from. */
function sourcesUnder(dir: string): string[] {
  return readdirSync(join(REPO, dir), { recursive: true, encoding: 'utf8' })
    .filter((one) => one.endsWith('.ts'))
    .map((one) => resolve(REPO, dir, one));
}

/**
 * Code with its comments taken out, because the claim read here is that no shipped command asks an origin, and
 * a source file may name a symbol in a sentence explaining what it does not call.
 */
function withoutComments(text: string): string {
  let out = '';
  let at = 0;
  while (at < text.length) {
    const pair = text.slice(at, at + 2);
    if (pair === '//') {
      const end = text.indexOf('\n', at);
      at = end < 0 ? text.length : end;
      continue;
    }
    if (pair === '/*') {
      const end = text.indexOf('*/', at + 2);
      at = end < 0 ? text.length : end + 2;
      continue;
    }
    const quote = pair[0] as string;
    if (quote === '"' || quote === "'" || quote === '`') {
      let next = at + 1;
      while (next < text.length && (text[next] !== quote || text[next - 1] === '\\')) {
        next += 1;
      }
      out += text.slice(at, Math.min(next + 1, text.length));
      at = next + 1;
      continue;
    }
    out += text[at] as string;
    at += 1;
  }
  return out;
}

describe('the origin prose of the shipped documents', () => {
  it('names only origins the package declares', () => {
    for (const [doc, text] of REGIONS) {
      for (const sentence of sentences(text)) {
        if (!declaredNameMentioned(sentence)) {
          continue;
        }
        for (const token of backticked(sentence)) {
          const shaped = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$/u.test(token);
          if (!shaped && !isOriginName(token)) {
            continue;
          }
          expect(DECLARED_ORIGINS, `${doc} cites ${token} as an origin name`).toContain(token);
        }
      }
    }
  });

  it('enumerates the read origins and the refused ones exactly', () => {
    const read = new Set<string>();
    const refused = new Set<string>();
    for (const [doc, text] of REGIONS) {
      for (const sentence of sentences(text)) {
        const named = namesInBackticks(sentence);
        if (named.length === 0) {
          continue;
        }
        if (/(neither|unread|refus)/iu.test(sentence)) {
          expect(named.sort(), `${doc}: the origins it calls refused`).toEqual([...UNREAD].sort());
          named.forEach((one) => refused.add(one));
          continue;
        }
        if (/read/iu.test(sentence)) {
          expect(named.sort(), `${doc}: the origins it calls read`).toEqual([...SERVED_ORIGINS].sort());
          named.forEach((one) => read.add(one));
        }
      }
    }
    expect([...read].sort(), 'the read origins are named in the prose').toEqual([...SERVED_ORIGINS].sort());
    expect([...refused].sort(), 'the refused origins are named in the prose').toEqual([...UNREAD].sort());
  });

  it('states the counts the lists carry', () => {
    for (const [doc, claim, expected] of COUNT_CLAIMS) {
      const prose = sentences(REGIONS.get(doc) as string).join(' ');
      const stated = claim.exec(prose);
      expect(stated, `${doc} states no count matching ${claim.source}`).not.toBeNull();
      expect((stated as RegExpExecArray).slice(1).map(counted), `${doc}: ${claim.source}`).toEqual(expected());
    }
  });

  it('cites entry points the package exports', () => {
    const exported = new Set([
      ...Object.keys(barrel),
      ...[...documentOf('packages/collateral/src/index.ts').matchAll(/export type \{([^}]*)\}/gu)]
        .flatMap((found) => (found[1] as string).split(','))
        .map((one) => one.trim().replace(/^type /u, ''))
        .filter((one) => one.length > 0 && one !== 'as const'),
    ]);
    const cited = new Set<string>();
    for (const [doc, text] of REGIONS) {
      for (const sentence of sentences(text)) {
        if (!declaredNameMentioned(sentence)) {
          continue;
        }
        for (const token of backticked(sentence)) {
          if (!/^[a-z][A-Za-z0-9]*$/u.test(token) || DOCUMENTED_OTHER_NAMES.includes(token) || isOriginName(token)) {
            continue;
          }
          cited.add(token);
          expect(exported.has(token), `${doc} cites ${token}, which @ashaveri/collateral does not export`).toBe(true);
        }
      }
    }
    expect([...cited].sort(), 'the entry points the prose cites by name').toEqual(['appraisePckCrl', 'appraiseVcekChain']);
  });

  it('keeps every declared origin named in the prose that describes them', () => {
    const named = new Set([...REGIONS.values()].flatMap((text) => sentences(text)).flatMap(namesInBackticks));
    expect([...named].sort(), 'a declared origin the prose stopped naming is a name it no longer carries')
      .toEqual([...DECLARED_ORIGINS].sort());
  });

  it('finds no shipped command asking an origin', () => {
    const files = SHIPPED_SOURCES.flatMap(sourcesUnder);
    expect(files.length, 'the shipped sources were read').toBeGreaterThan(20);
    const text = files.map((one) => readFileSync(one, 'utf8'));
    const code = text.map(withoutComments).join('\n');
    for (const name of ORIGIN_ASKING_NAMES) {
      expect(new RegExp(`\\b${name}\\b`, 'u').test(code), `a shipped command names ${name}`).toBe(false);
    }
    // The scanner reads code rather than an empty string: the one appraisal entry point a shipped command does
    // call weighs material a caller hands over, and `requestUrl` is still named in a source comment, which the
    // stripping above takes out while leaving the call sites.
    expect(/\bappraiseCarriedCollateral\b/u.test(code), 'the carried appraisal is the shipped half').toBe(true);
    expect(text.some((one) => /requestUrl/u.test(one)), 'the comment naming requestUrl is still there').toBe(true);
  });
});
