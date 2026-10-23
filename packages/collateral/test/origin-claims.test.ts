import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
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
 * The names-and-counts gate over the origin prose of three documents and over the package's own description.
 *
 * A sentence about which origins are read is a claim about a list, and a list changes in code without changing
 * the sentence beside it. This suite reads `docs/error-codes.md`, `docs/threat-model.md` and `README.md` and
 * holds what they say about origins to `DECLARED_ORIGINS` and `SERVED_ORIGINS`: a name the prose cites as an
 * origin is one the package declares, an enumeration of the read origins is exactly the ones it reads, an
 * enumeration of the refused ones exactly the remainder, and a count stated beside those sentences is the
 * length of the list it counts. The `description` field of `package.json` carries the same kind of claim in the
 * shortest form there is, and nothing else in the estate reads it, so each verb it states is held to the
 * declaration fact that says how many origins answer with that verb. Entry points the prose names are checked against the package's exports, so a
 * rename lands here rather than in a document a caller trusts, and the two entry points the revocation list and
 * the certificate chain are cited through are required to be named while no list of the further names is
 * fixed. A sentence about which suites hold a document's claims names files, so it is read out of the files: each
 * suite known to hold one of those claims has to stay named there, and every name the sentence carries has to
 * belong to a test that reads that document. The claim that no shipped command asks an origin is read out of the
 * sources of the shipped commands rather than out of the prose that states it.
 *
 * What stays a reader's work is the argument inside a sentence and which claim of the section each named holder
 * answers, since a name only has to belong to a file that reads the document. The vocabulary below names the
 * backticked words that are material facts rather than symbols of this package.
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

/**
 * Every name that reaches an origin, or that builds or reads what an origin sends back.
 *
 * The roster is what the sentence over this package's fetching rests on: a shipped command naming any of these
 * outside a comment is a shipped command asking a vendor, which the documents state it does not do.
 * `appraiseOcspResponse` is one because it writes the question from the two certificates a caller names and
 * posts it through the same `observe` the other appraisals fetch through; `readRimManifest` is not, because a
 * manifest reading takes the bytes it was handed and asks nothing of the host that would carry them.
 */
const ORIGIN_ASKING_NAMES = [
  'fetchFromOrigin',
  'readServedCollateral',
  'requestUrl',
  'appraiseCollateral',
  'appraisePckCrl',
  'appraiseVcekChain',
  'appraiseOcspResponse',
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

/**
 * The count a spelling states, digits or a number word, or nothing for a spelling this estate does not read.
 * Nothing is raised here: a run that stopped at an odd spelling would cancel the report of every other count,
 * which is the behaviour the collection below exists to avoid.
 */
function counted(spelling: string): number | undefined {
  const word = NUMBER_WORDS[spelling.toLowerCase()];
  if (word !== undefined) {
    return word;
  }
  return /^\d+$/u.test(spelling) ? Number(spelling) : undefined;
}

/**
 * The declarations whose reader answers with a served JSON document, which is the figure the Intel JSON sentences
 * count. One list holds the filter and each entry reads its length, because two copies of the same filter can
 * disagree while each still reads as the list it came from.
 */
const SERVED_JSON_DOCUMENTS = Object.values(ORIGIN_DECLARATIONS)
  .filter((one) => one.reader.as === 'served-json-document');

/**
 * The counts the package's own description states each of its verbs of.
 *
 * A description is a claim about the whole package that no document repeats, so each verb is held to the
 * declaration fact that says how many origins answer with it: a host is the address an origin is fetched at and
 * a refusal table what it is answered with, both stated by every declaration, a cache rule is what a kept answer
 * is a record of, and the wrapper reader the one arm that answers no verdict about the bytes it read, because the
 * appraisal path replies to it with the missing-context refusal naming what that reader lacks.
 */
const DECLARATIONS = Object.values(ORIGIN_DECLARATIONS);
const VERB_COUNTS: Readonly<Record<string, number>> = {
  fetch: DECLARATIONS.filter((one) => one.host.length > 0).length,
  classify: DECLARATIONS.filter((one) => one.reader.as !== 'rim-wrapper').length,
  retain: DECLARATIONS.filter((one) => one.cache !== null).length,
  refuse: DECLARATIONS.filter((one) => Object.keys(one.refusals).length > 0).length,
};

/**
 * The count a verb of the description is claimed of, which is the first count of origins printed after it.
 *
 * A clause that claims two verbs and states one count claims both of that count, which is what makes a wording
 * widened past the declarations read here rather than left for whoever reads the package page.
 */
function claimedCount(description: string, verb: string): number | undefined {
  const at = description.toLowerCase().indexOf(verb);
  if (at < 0) {
    return undefined;
  }
  const stated = /\b([a-z0-9]+) origins?\b/u.exec(description.slice(at));
  return stated === null ? undefined : counted(stated[1] as string);
}

/**
 * The counts the documents state about origins, each beside the sentence that states it, and the list each count
 * is a fact about. A sentence that counts a list counts it as the package declares it or the run fails. One
 * derived figure can back the same wording in more than one document, and then every document listed carries
 * the claim, so a list that moves turns each sentence that states its length red at once. A sentence that states
 * one of those figures in words of its own shape is its own entry keyed to the document that carries it, since
 * a figure read only through one pattern leaves a sentence written another way free to go false unremarked.
 */
const COUNT_CLAIMS: readonly (readonly [docs: readonly string[], claim: RegExp, counts: () => number[]])[] = [
  [
    [ERROR_CODES],
    /the grid has (\w+) rows, one for each pair of the (\w+) origins named by `SERVED_ORIGINS` and the (\w+) members of `CollateralErrorCode`/iu,
    () => [SERVED_ORIGINS.length * CODES.length, SERVED_ORIGINS.length, CODES.length],
  ],
  [[ERROR_CODES], /not one of the (\w+) cells reads `not exercised`/iu, () => [SERVED_ORIGINS.length * CODES.length]],
  [
    [ERROR_CODES],
    /its rows are the (\w+) origins `SERVED_ORIGINS` names crossed with the (\w+) members of `CollateralErrorCode`/iu,
    () => [SERVED_ORIGINS.length, CODES.length],
  ],
  [
    [ERROR_CODES],
    /the origins described as read are the (\w+) `SERVED_ORIGINS` names/iu,
    () => [SERVED_ORIGINS.length],
  ],
  [[THREAT_MODEL], /declares (\w+) origins and reads (\w+)/iu, () => [DECLARED_ORIGINS.length, SERVED_ORIGINS.length]],
  [[README], /names (\w+) origins and reads (\w+)/iu, () => [DECLARED_ORIGINS.length, SERVED_ORIGINS.length]],
  [
    [README, THREAT_MODEL],
    /the (\w+) intel json documents/iu,
    () => [SERVED_JSON_DOCUMENTS.length],
  ],
  [
    [THREAT_MODEL],
    /its (\w+) json document addresses/iu,
    () => [SERVED_JSON_DOCUMENTS.length],
  ],
];

/** The closing section, which states which suites hold the claims this file makes about itself. */
const KEEPING = section(documentOf(ERROR_CODES), KEEPING_HEADING);

const REGIONS: ReadonlyMap<string, string> = new Map([
  [ERROR_CODES, `${section(documentOf(ERROR_CODES), GRID_HEADING)} ${KEEPING}`],
  [THREAT_MODEL, bullet(documentOf(THREAT_MODEL), THREAT_MARKER)],
  [README, section(documentOf(README), README_HEADING)],
]);

/**
 * The test files the opening sentence names. The sentence is a claim about files, so it is read out of the files:
 * each suite known to hold one of the section's claims has to appear in it, and every name it carries has to
 * belong to a file that reads this document.
 */
function namedHolders(): string[] {
  const lead = sentences(KEEPING)[0] as string;
  return [...new Set(backticked(lead).filter((token) => /\.test\.ts$/u.test(token)))];
}

/**
 * The suites known to hold a claim of that section: the union-table suite, the grid suite, and this one. A name
 * can drop out while the list still reads as a list of readers, and then a claim of the section sits with a
 * suite that sentence stopped naming.
 */
const CLAIM_HOLDERS = [
  'packages/fixtures/test/error-codes.test.ts',
  'packages/collateral/test/refusal-reachability.test.ts',
  'packages/collateral/test/origin-claims.test.ts',
];

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
    const unstated: string[] = [];
    const mismatched: string[] = [];
    for (const [docs, claim, expected] of COUNT_CLAIMS) {
      for (const doc of docs) {
        const prose = sentences(REGIONS.get(doc) as string).join(' ');
        const stated = claim.exec(prose);
        if (stated === null) {
          unstated.push(`${doc} states no count matching ${claim.source}`);
          continue;
        }
        const figures: number[] = [];
        const unreadable: string[] = [];
        for (const spelling of stated.slice(1)) {
          const figure = counted(spelling);
          if (figure === undefined) {
            unreadable.push(spelling);
            continue;
          }
          figures.push(figure);
        }
        if (unreadable.length > 0) {
          mismatched.push(
            `${doc}: ${claim.source} spells ${unreadable.join(',')} where a count is a digit or a number word`,
          );
          continue;
        }
        if (figures.join(',') !== expected().join(',')) {
          mismatched.push(`${doc}: ${claim.source} reads ${figures.join(',')} where the lists carry ${expected().join(',')}`);
        }
      }
    }
    // Both lists are collected rather than raised one claim at a time, because one derived figure can back
    // several sentences, and a run that stops at the first mismatch leaves the rest of them to the reader.
    expect(unstated, 'a count claim with no sentence behind it').toEqual([]);
    expect(mismatched, 'a count the prose states and the lists deny').toEqual([]);
  });

  it('holds the package description to the declaration facts its verbs rest on', () => {
    const described = JSON.parse(documentOf('packages/collateral/package.json')) as { readonly description?: string };
    const description = described.description ?? '';
    expect(description, 'packages/collateral/package.json states no description').not.toBe('');
    const mismatches: string[] = [];
    for (const [verb, holds] of Object.entries(VERB_COUNTS)) {
      const stated = claimedCount(description, verb);
      if (stated === undefined) {
        mismatches.push(`the description claims no ${verb} beside a count of origins`);
        continue;
      }
      if (stated !== holds) {
        mismatches.push(`the description claims ${verb} of ${String(stated)} origins and the declarations state it of ${String(holds)}`);
      }
    }
    expect(mismatches, `what ${description} says an origin is fetched, classified, retained or refused`).toEqual([]);
  });

  /**
   * The sentence naming the suites that hold this document's claims is a claim about files, and a list of files
   * that drifts from the readers on disk is a false count about this suite. It is read out of the files: every
   * holder the section names has to stay named there, and each name has to be a file that reads the document.
   * Which claim of the section each name answers is not read here, because the files do not say.
   */
  it('names the suites holding its claims as the files that read this document', () => {
    const holders = namedHolders();
    for (const holder of CLAIM_HOLDERS) {
      expect(holders, `${holder} holds a claim the closing section states, and its sentence stopped naming it`).toContain(holder);
    }
    for (const file of holders) {
      expect(existsSync(join(REPO, file)), `${file} is named as a holder and is not a file`).toBe(true);
      expect(documentOf(file), `${file} is named as a holder and does not read ${ERROR_CODES}`).toContain(ERROR_CODES);
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
    // The two entry points the revocation list and the certificate chain are cited through have to be named, and
    // a sentence citing any further entry point is held to the export rule alone rather than to the inventory
    // written down so far: a list of every citation would refuse a truer sentence about a real export.
    for (const needed of ['appraisePckCrl', 'appraiseVcekChain']) {
      expect([...cited], `${needed} is no longer cited by the origin prose`).toContain(needed);
    }
  });

  it('keeps every declared origin named in the prose that describes them', () => {
    const named = new Set([...REGIONS.values()].flatMap((text) => sentences(text)).flatMap(namesInBackticks));
    expect([...named].sort(), 'a declared origin the prose stopped naming is a name it no longer carries')
      .toEqual([...DECLARED_ORIGINS].sort());
  });

  it('finds no shipped command asking an origin', () => {
    const files = SHIPPED_SOURCES.flatMap(sourcesUnder);
    expect(files.length, 'the shipped sources were read').toBeGreaterThan(20);
    const raw = files.map((file) => readFileSync(file, 'utf8'));
    const stripped = raw.map((one) => withoutComments(one));
    const code = stripped.join('\n');
    // Two controls over the scanner, one for each half of what it has to do, so that the absence loop below is
    // read out of text known to be each file's own code with only its comments taken out. `requestUrl` is named
    // by a shipped source only inside a comment, so the text read from disk carries it while the stripped text
    // has to lose it; `appraiseCarriedCollateral` names the appraisal a shipped command does call, so the
    // stripped text has to carry it still. A scanner that takes nothing out fails the second control and one
    // that swallows a file past its head fails the third. Each message carries both premises the control can
    // fail on, because a scanned source whose comment or call site moved reads exactly like a scanner that
    // misbehaved, and the named file is where a moved fact is checked.
    expect(raw.some((one) => /\brequestUrl\b/u.test(one)), 'a shipped source comment names requestUrl').toBe(true);
    expect(
      /\brequestUrl\b/u.test(code),
      'the stripped text names requestUrl, so either the stripping took no comment out or a shipped source ' +
        'names it outside a comment: the comment is in packages/cli/src/commands/carried-collateral.ts',
    ).toBe(false);
    expect(
      /\bappraiseCarriedCollateral\b/u.test(code),
      'the stripped text lost appraiseCarriedCollateral, so either the stripping swallowed code or no shipped ' +
        'command calls it any more: the call sites are packages/cli/src/commands/carried-collateral.ts and ' +
        'packages/cli/src/commands/verify-receipt.ts',
    ).toBe(true);
    for (const name of ORIGIN_ASKING_NAMES) {
      expect(new RegExp(`\\b${name}\\b`, 'u').test(code), `a shipped command names ${name}`).toBe(false);
    }
    // One control per scanned file rather than existentially over the joined text, which is what proves each
    // file the list holds survived the scan with its head intact: a module edge, an import or export statement
    // outside its comments. A scanner that swallowed the text after that edge keeps passing here, so these
    // controls say nothing about the rest of a file, and the two controls above are existential over the
    // joined text: a scanner that swallowed every body but the files carrying those two names would satisfy
    // them, so what they cover is the rest of at least one file each.
    for (const [index, file] of files.entries()) {
      expect(/^(?:import|export)\b/mu.test(stripped[index] as string), `${file} keeps a module edge outside its comments`).toBe(true);
    }
  });
});
