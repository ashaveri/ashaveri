import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  captureRecordKey,
  fromBase64Url,
  importEnvelopeKey,
  parseCaptureRecord,
  parseImportEnvelope,
  toHex,
} from '@ashaveri/sdk';

/**
 * The secret scan's allowlist, written from the bytes it exempts rather than copied out of a fixture.
 *
 * A block in `.gitleaks.toml` is a standing exemption for one value in one file, so an entry has to be earned
 * by something a reader can check. Copying a digest out of a vector earns nothing: the characters are in the
 * file either way, and a scan reading commits cannot tell the address of a published record from a credential
 * that reached the tree by mistake. This script earns it a second way. It reads each candidate out of a file at
 * the shape a built-in rule keys a name to a token on, recomputes that value over other bytes of this tree, and
 * refuses the candidate when no bytes it can name digest to it. A value that passes is the address of something
 * this repository publishes, and the run prints whose bytes.
 *
 * What does not pass stays hand-written in `HAND_BLOCKS`, where each entry names where its bytes come from. A
 * signing key made by taking sha256 of a seed label is not the address of anything the file publishes: the same
 * arithmetic turns a hashed passphrase into a credential, so a rule admitting a value for being a digest of any
 * string would admit that one too. Only a digest taken over bytes the tree carries as a published document,
 * record or public half is admitted.
 *
 * The run exits 1 and writes nothing when a file states a candidate the script cannot account for, and the
 * vectors job compares the committed config against this output, so an exemption nobody read is a red check
 * rather than a review finding.
 */

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));

/** The repository whose scan config is written: three directories above `packages/fixtures/scripts`. */
const DEFAULT_ROOT = resolve(SCRIPT_DIR, '..', '..', '..');

/** The column the written comment paragraphs wrap at. */
const COMMENT_WIDTH = 108;

/** One value a file states at a shape a built-in rule reads, and the first line stating it. */
interface Candidate {
  readonly value: string;
  readonly line: number;
}

/** One value the bytes of this tree digest, named beside the phrase saying which bytes. */
interface Address {
  readonly value: string;
  readonly witness: string;
}

/** One file whose published bytes carry values the scan reads as candidates. */
interface DerivedFile {
  /** Repository-relative path, which is the one path the emitted block names. */
  readonly path: string;
  /** The block's `description`. */
  readonly description: string;
  /** A candidate's shape in this file, with the value in capture group one. */
  readonly pattern: string;
  /** The lines of the one paragraph naming what the block exempts and why, written ahead of it. */
  readonly reason: readonly string[];
  /** The addresses this file's own bytes carry, each naming the bytes the digest is taken over. */
  readonly addresses: (text: string) => readonly Address[];
}

/** One exemption no script writes: what it is, and where its bytes come from, both stated in words. */
interface HandBlock {
  readonly path: string;
  readonly value: string;
  readonly description: string;
  readonly reason: readonly string[];
}

/**
 * The capture suite's record keys. Each accepted row publishes `recordKey` beside the record it is taken over,
 * so a row carries both halves of the proof: the shipped digest runs over one half and is compared to the other.
 * A row whose record the shipped reader will not take yields no address, so its stated key reaches no block and
 * the run refuses it rather than dying on the row.
 */
function captureAddresses(text: string): readonly Address[] {
  const file = JSON.parse(text) as {
    readonly vectors: readonly { readonly name: string; readonly record?: unknown }[];
  };
  return file.vectors
    .filter((row) => row.record !== undefined)
    .flatMap((row, index) => {
      const witness = `the canonical JSON of the record at \`vectors[${String(index)}]\`, the row named \`${row.name}\``;
      try {
        return [{ value: captureRecordKey(parseCaptureRecord(row.record)), witness }];
      } catch {
        return [];
      }
    });
}

/**
 * The import suite's content keys. Each accepted row publishes `key` beside the envelope whose content the key is
 * taken over: the version, the provider and the original, with the intake stamp and the derived rows outside it,
 * which is what makes a second intake of one export carry the key of the first. A row whose envelope the shipped
 * reader will not take yields no address, for the same reason as above.
 */
function importAddresses(text: string): readonly Address[] {
  const file = JSON.parse(text) as {
    readonly vectors: readonly { readonly name: string; readonly envelope?: unknown }[];
  };
  return file.vectors
    .filter((row) => row.envelope !== undefined)
    .flatMap((row, index) => {
      const witness =
        `the canonical JSON of the version, provider and original of the envelope at \`vectors[${String(
          index,
        )}]\`, the row named \`${row.name}\``;
      try {
        return [{ value: importEnvelopeKey(parseImportEnvelope(row.envelope)), witness }];
      } catch {
        return [];
      }
    });
}

/**
 * The epoch inventory's key identifiers. `layout.keyMaterial` publishes each key's public half, and the writer
 * demands an identifier that is sha256 of that half, so the bytes an identifier addresses sit in the same array.
 */
function epochAddresses(text: string): readonly Address[] {
  const file = JSON.parse(text) as {
    readonly layout: { readonly keyMaterial: readonly { readonly id: string; readonly publicKeyBase64Url: string }[] };
  };
  return file.layout.keyMaterial.map((row, index) => ({
    value: toHex(sha256(fromBase64Url(row.publicKeyBase64Url))),
    witness: `the public half published at \`layout.keyMaterial[${String(index)}]\`, the key named \`${row.id}\``,
  }));
}

const DERIVED_FILES: readonly DerivedFile[] = [
  {
    path: 'packages/fixtures/data/epoch-inventory-v1.json',
    description: "The epoch inventory fixture's key identifiers, in the file that publishes them",
    pattern: String.raw`key kid=([0-9a-f]{64})`,
    reason: [
      'An identifier rather than a key. The inventory readers that answer a kid mismatch spell their refusal as `header',
      'kid=<hex> key kid=<hex>`, and this suite publishes that sentence verbatim, so the built-in generic-api-key rule',
      'reads the `key kid=` prefix and the sixty-four hex characters behind it as a credential candidate. Every value',
      'admitted below is sha256 of a public half printed in this same file, in the `layout.keyMaterial` row beside it,',
      'and the script takes that digest over those bytes before the line naming it is written. What the block exempts',
      'is an address of a published key, and nothing secret is named.',
    ],
    addresses: epochAddresses,
  },
  {
    path: 'packages/fixtures/data/capture-v1.json',
    description: "The capture fixture's record keys, in the file that publishes them",
    pattern: String.raw`"recordKey": "([0-9a-f]{64})"`,
    reason: [
      'An identifier rather than a key, in the same shape as the block above. Every accepted row of this suite',
      'publishes `recordKey`, which is sha256 of that record under the domain prefix `captureRecordKey` states, and the',
      'built-in generic-api-key rule reads the `"recordKey":` prefix plus the sixty-four hex characters behind it as a',
      'credential candidate. Every value admitted below is the address of bytes the same row already prints: the script',
      'runs the shipped `captureRecordKey` over the record beside each one and admits only what it reproduces. A row',
      'whose stated key is not its record\'s digest is refused by the suite that replays them, and by this script before',
      'a block carrying it is written.',
    ],
    addresses: captureAddresses,
  },
  {
    path: 'packages/fixtures/data/import-v1.json',
    description: "The import envelope's content keys, in the file that publishes the vectors",
    pattern: String.raw`"key": "([0-9a-f]{64})"`,
    reason: [
      'An identifier rather than a key, in the same shape as the two blocks above. Every accepted row publishes `key`,',
      'which is sha256 of the version, the provider and the original of its envelope under the domain prefix',
      '`importEnvelopeKey` states, and the rule reads that name beside a long token as a credential candidate. The',
      'script runs the shipped key function over each row\'s own envelope and admits only what it reproduces, so the',
      'row that states a second intake of one export is covered by the same value as the row it restates rather than by',
      'an extra line.',
    ],
    addresses: importAddresses,
  },
];

/**
 * The exemptions no script writes. Each is a value the scan reads as a candidate at one path and no bytes of this
 * tree are the address of, so what it is and where its bytes come from are stated in words rather than derived.
 */
const HAND_BLOCKS: readonly HandBlock[] = [
  {
    path: 'packages/fixtures/data/pop-v1.json',
    value: 'd1332ee54c62ab3f5336167d4d694944ed98509395a5529e165e043013de19dd',
    description: "The PoP fixture's signing key, in the file that publishes it",
    reason: [
      'One of the two deterministic test signing keys this repository publishes deliberately, each in the same object',
      'as the public half it pairs with, so a scanner with no context has to be told it is not a credential. Its bytes',
      "come from `signingKeyFromSeed(labeled('pop-vector-key-v1/private'))` in",
      '`packages/fixtures/scripts/pop-vectors.ts`. A digest of a seed label is a key and not the address of the file',
      'that prints it, so this line stays hand-written with the seed named beside it. The file is generated, so a value',
      'pasted over its slot fails the job that regenerates it as well as the scan.',
    ],
  },
  {
    path: 'packages/fixtures/data/keys/receipt-key-v1.json',
    value: '83323642bdd8d84c58b3d208d07b4dfc7d84be7b4d670d2272a7ea328f2a06b7',
    description: "The receipt fixture's signing key, in the file that publishes it",
    reason: [
      'The second deterministic test signing key. Its bytes come from',
      "`labeled('ashaveri-fixtures/receipt-key/v1')`, the seed `fixtureKey()` in",
      '`packages/fixtures/scripts/receipt-envelope.ts` hands to `signingKeyFromSeed`, and the receipt fixtures beside',
      'it are sealed under it. A seed digest again, so a key rather than an address. The file is generated, so a value',
      'pasted over its slot fails the job that regenerates it as well as the scan.',
    ],
  },
  {
    path: 'README.md',
    value: 'E6uO0ed3_zm-Ix32lLu8j5Z9W3eet8q1WHYstU-WCwU',
    description: "The receipt fixture's public verification key, in the README example that prints it",
    reason: [
      'The public half of the key above, and the verification half rather than the signing half, so the private bytes',
      'stay outside this block. It is exempted at the one place a document prints it: the verify-pack example, where',
      'the same thirty-two bytes appear base64url rather than hex and the sentence under the example names the file',
      'that publishes them. Base64url of a curve point is an encoding of bytes and not a digest of them, so no script',
      'writes this line; the bytes come from `data/keys/receipt-key-v1.json` beside its private half.',
    ],
  },
  {
    path: 'gateway/test/receipt-provenance.test.ts',
    value: 'CANARY-4f7b2e9a',
    description: "The provenance case's canary marker, in the file that asserts it goes nowhere",
    reason: [
      "A marker rather than a key. The gateway's provenance case puts one short string in the prompt, the completion,",
      'the model id and the credential of every request it issues, then asserts that string reaches none of the',
      "receipt's text members. The value authenticates nothing, and eight hex characters behind a word is too short for",
      'any real credential to be. The built-in generic-api-key rule matched it at the line that declared the constant',
      'under the name `TOKEN`, because that rule reads the name beside the value rather than what the value is worth.',
      'The constant carries the name the case uses for the thing, so no line of the current tree matches it, and this',
      'block answers for the commit that introduced the shape, which stays in the history whatever the constant is',
      'called after it. Nothing digests to this value, so nothing derives it.',
    ],
  },
  {
    path: 'packages/fixtures/data/challenge-v1.json',
    value: 'tH4RCNZJrs5MOILOyEcYYDm_3i1hbJ-WxCq0t4zm-xY',
    description: 'The session public key the challenge family states, in the file that publishes it',
    reason: [
      'The public half of a session key pair, published so a reader can lay the challenge pre-image out without this',
      "repository's code, and the built-in rule reads that forty-three character base64url run beside its name as a",
      'candidate. Nothing new is disclosed by it: the bytes are the `pk` member of the `enc` arm of',
      '`data/receipts/receipt-enc-session-v2.cbor`, the signed document this repository already publishes, and',
      '`decodeReceipt` answers them equal to the value the block below names. A reader handed that document already',
      'holds them. An encoding of a CBOR member is not a digest of anything, so this line stays hand-written and names',
      'the document instead. The file is generated, so a value pasted over its slot fails the job that regenerates it',
      'as well as the scan.',
    ],
  },
];

/** The paragraphs at the head of the written file: what the blocks enforce, and how an entry is earned. */
const HEADER: readonly (readonly string[])[] = [
  [
    "The rules that find candidates are gitleaks' own and this file only extends them. That distinction is",
    'load-bearing: a config that lists allowlists without `useDefault` replaces the built-in rule set with an empty',
    'one, which reports nothing on a tree holding live credentials and reads exactly like a clean repository.',
    'Measured on 8.30.1, deleting the two lines below turned a repository holding a fabricated npm token into a scan',
    'that passed.',
  ],
  [
    'Each block below exempts the intersection of one value list and one path, and no two files share a block.',
    "Measured on a copy of this repository: the PoP fixture's key held by the receipt fixture's file is reported, and",
    'so is a third key planted inside either file, while two blocks joined into one exempt the cross product of their',
    'values and their paths and let the first of those through. The value half of the pairing is enforced when a scan',
    'reads commits, which is how CI runs it, and not when a scan reads a working tree: on one tree, one config and',
    '8.30.1 the commit scan reported a second key planted inside a file named below and the working-tree scan',
    'reported nothing.',
  ],
  [
    'This file is written, not copied. `pnpm -C packages/fixtures generate:scan-allowlist` produces it from',
    '`packages/fixtures/scripts/derive-scan-allowlist.ts`, and the vectors job runs that command and refuses a diff.',
    'A block is admitted only when the value it names is the digest of bytes this tree carries as something',
    'published, and the run prints whose bytes; a value with no address to name is written in `HAND_BLOCKS` inside',
    'that script instead, where it has to state what it is and where its bytes come from before it exempts anything.',
    'A scan run with `--redact` never prints the value it found, so no line here is authored out of a log.',
  ],
];

/** The values a file states at its shape, each with the first line stating it, and the count of occurrences. */
function candidatesAt(
  text: string,
  pattern: string,
): { readonly at: readonly Candidate[]; readonly occurrences: number } {
  const shape = new RegExp(pattern, 'gu');
  const at: Candidate[] = [];
  const seen = new Set<string>();
  let occurrences = 0;
  for (const match of text.matchAll(shape)) {
    occurrences += 1;
    const value = match[1];
    if (value === undefined || seen.has(value)) continue;
    seen.add(value);
    at.push({ value, line: text.slice(0, match.index).split('\n').length });
  }
  return { at, occurrences };
}

/** What one derived file yields: the values admitted over both halves of the pairing, the candidates refused
 *  because nothing digests to them, and the addresses that reach no block because no rule reads their shape. */
interface AdmittedValue {
  readonly value: string;
  readonly line: number;
  readonly witness: string;
}

interface Derivation {
  readonly file: DerivedFile;
  readonly admitted: readonly AdmittedValue[];
  readonly refused: readonly Candidate[];
  readonly unquoted: readonly Address[];
  readonly occurrences: number;
}

function derive(file: DerivedFile, text: string): Derivation {
  const stated = candidatesAt(text, file.pattern);
  const addresses = new Map(file.addresses(text).map((one) => [one.value, one]));
  const admitted: AdmittedValue[] = [];
  const refused: Candidate[] = [];
  for (const candidate of stated.at) {
    const address = addresses.get(candidate.value);
    if (address === undefined) refused.push(candidate);
    else admitted.push({ value: candidate.value, line: candidate.line, witness: address.witness });
  }
  const quoted = new Set(stated.at.map((one) => one.value));
  return {
    file,
    admitted: admitted.sort((a, b) => (a.value < b.value ? -1 : 1)),
    refused,
    unquoted: [...addresses.values()].filter((one) => !quoted.has(one.value)),
    occurrences: stated.occurrences,
  };
}

/** A literal, anchored and escaped, spelled the way the hand-written file this script replaces spelled it. */
function literal(value: string): string {
  return `'''^${value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}$'''`;
}

/** One paragraph, wrapped at `COMMENT_WIDTH` without breaking a token. */
function wrap(paragraph: string): readonly string[] {
  const lines: string[] = [];
  let current = '';
  for (const word of paragraph.split(' ')) {
    if (current !== '' && `# ${current} ${word}`.length > COMMENT_WIDTH) {
      lines.push(`# ${current}`);
      current = word;
      continue;
    }
    current = current === '' ? word : `${current} ${word}`;
  }
  if (current !== '') lines.push(`# ${current}`);
  return lines;
}

/** The comment ahead of one block: every paragraph, one blank comment line apart. */
function comment(paragraphs: readonly (readonly string[])[]): readonly string[] {
  return paragraphs
    .map((paragraph) => paragraph.join(' '))
    .flatMap((one) => [...wrap(one), '#'])
    .slice(0, -1);
}

/** A block: one description, the values it names, and the one path they are exempted at. */
function block(description: string, values: readonly string[], path: string): readonly string[] {
  const listed = values.map((value, index) =>
    index === values.length - 1 ? `  ${literal(value)}` : `  ${literal(value)},`,
  );
  return [
    '[[allowlists]]',
    `description = "${description}"`,
    'condition = "AND"',
    'regexTarget = "secret"',
    'regexes = [',
    ...listed,
    ']',
    'paths = [',
    `  ${literal(path)}`,
    ']',
  ];
}

/** The census a derived block carries, both counts read off the file the block names. */
function censusOf(one: Derivation): readonly (readonly string[])[] {
  const values = one.admitted.length;
  const stated = one.occurrences;
  const census = [
    `${String(values)} ${values === 1 ? 'value is' : 'values are'} admitted at this path, each one recomputed over`,
    'bytes this tree publishes before the line naming it is written.',
    stated === values
      ? 'This file states each of them once, so the block names as many values as the file states.'
      : `This file states them ${String(stated)} times, because rows that hold one record and state one key share`,
    stated === values ? '' : 'a value.',
  ].filter((line) => line !== '');

  const extra = one.unquoted.length;
  if (extra === 0) return [census];
  const unquoted =
    extra === 1
      ? 'One further digest is recomputed here and reaches no block below: this file publishes it at no shape a' +
        ' built-in rule reads, so an exemption naming it would be a permission with no finding under it.'
      : `${String(extra)} further digests are recomputed here and reach no block below: this file publishes them at` +
        ' no shape a built-in rule reads, so an exemption naming them would be a permission with no finding under it.';
  return [census, unquoted.split(' ')];
}

/** The config, as one string, derived from the tree rooted at `root`. */
function renderScanConfig(root: string): { readonly text: string; readonly derivations: readonly Derivation[] } {
  const derivations = DERIVED_FILES.map((file) => derive(file, readFileSync(join(root, file.path), 'utf8')));
  const lines: string[] = [
    'title = "Ashaveri secret scan configuration"',
    '',
    ...comment(HEADER),
    '',
    '[extend]',
    'useDefault = true',
    '',
  ];

  for (const one of derivations) {
    lines.push(...comment([[...one.file.reason], ...censusOf(one)]));
    lines.push('');
    lines.push(...block(one.file.description, one.admitted.map((each) => each.value), one.file.path));
    lines.push('');
  }

  for (const hand of HAND_BLOCKS) {
    lines.push(...comment([[...hand.reason]]));
    lines.push('');
    lines.push(...block(hand.description, [hand.value], hand.path));
    lines.push('');
  }

  return { text: `${lines.join('\n').replace(/\n+$/u, '\n')}\n`, derivations };
}

/** Where a hand-written value sits in the file its block names, read out of that file rather than assumed. */
function stateOf(hand: HandBlock, root: string): string {
  const text = readFileSync(join(root, hand.path), 'utf8');
  const line = text.split('\n').findIndex((each) => each.includes(hand.value));
  return line === -1
    ? `${hand.path}: hand-written, and no line of this path states the value now, so the block answers for the history`
    : `${hand.path}: hand-written, value stated at line ${String(line + 1)} of this path`;
}

/** What the run says about the tree it read, and the candidates it could not account for. */
function report(derivations: readonly Derivation[], root: string): readonly Candidate[] {
  const refused: Candidate[] = [];
  for (const one of derivations) {
    console.log(
      `${one.file.path}: ${String(one.admitted.length)} value(s) admitted over ${String(one.occurrences)} stated` +
        ` occurrence(s); ${String(one.unquoted.length)} recomputed digest(s) reach no shape the scan reads`,
    );
    for (const each of one.admitted) console.log(`  line ${String(each.line)} admitted: sha256 of ${each.witness}`);
    for (const each of one.unquoted) console.log(`  no block written: sha256 of ${each.witness}`);
    for (const each of one.refused) {
      console.error(
        `  ${one.file.path} line ${String(each.line)} refused: the file states a value where the scan reads a` +
          ' candidate, and no bytes this tree carries are the address of it',
      );
      refused.push(each);
    }
  }
  for (const hand of HAND_BLOCKS) console.log(stateOf(hand, root));
  return refused;
}

const rootArgument = process.argv.indexOf('--root');
const ROOT = rootArgument === -1 ? DEFAULT_ROOT : resolve(process.argv[rootArgument + 1] ?? DEFAULT_ROOT);
const rendered = renderScanConfig(ROOT);
const refusals = report(rendered.derivations, ROOT);

if (refusals.length > 0) {
  console.error(
    `refused: ${String(refusals.length)} unexplained candidate(s), so nothing was written. An exemption is earned by` +
      ' the bytes behind the value, not by the value.',
  );
  process.exit(1);
}

writeFileSync(join(ROOT, '.gitleaks.toml'), rendered.text, 'utf8');
console.log(`wrote ${join(ROOT, '.gitleaks.toml')}`);
