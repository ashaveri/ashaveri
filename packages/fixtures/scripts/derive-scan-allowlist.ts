import { existsSync, readFileSync, writeFileSync } from 'node:fs';
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
 * Which files carry candidates, and the kind of arithmetic that earns each one, are read from `scan-allowlist.json`
 * at the scanned root rather than written here. The roster is data: one entry per candidate set, stating its path,
 * the shape the scan reads there, the name of the rule that recomputes it, and the reason paragraph the emitted
 * block carries. What does not pass stays hand-written in the roster's `hand-written` class, where each entry
 * states the value it exempts and says whether a line of its path still carries it. A signing key made by taking
 * sha256 of a seed label is not the address of anything the file publishes: the same arithmetic turns a hashed
 * passphrase into a credential, so a rule admitting a value for being a digest of any string would admit that one
 * too. Only a digest taken over bytes the tree carries as a published document, record or public half is admitted.
 *
 * The arithmetic is the part that stays here, and the vocabulary of rule names is closed: a roster that names a
 * rule no implementation answers is refused with its file named, never read as a default. That is what lets a
 * second repository adopt this control by writing its own roster at its own root instead of copying a rule, since
 * a copied rule drifts from the one that decides.
 *
 * The run exits 1 and writes nothing when the roster states a candidate nothing digests to, names a rule or a
 * field the script does not answer, points at a path this root does not carry, or states a hand-written value the
 * bytes at its path no longer hold. The vectors job compares the committed config against this output, so an
 * exemption nobody read is a red check rather than a review finding.
 */

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));

/** The repository whose scan config is written: three directories above `packages/fixtures/scripts`. */
const DEFAULT_ROOT = resolve(SCRIPT_DIR, '..', '..', '..');

/** The column the written comment paragraphs wrap at. */
const COMMENT_WIDTH = 108;

/** The roster's path at the scanned root: which files carry candidates, and which rule earns each one. */
const ROSTER_PATH = 'scan-allowlist.json';

/** The one version of the roster this script reads, refused rather than assumed about any other. */
const ROSTER_VERSION = 1;

/** The rule class that recomputes nothing, whose entries state the bytes they exempt and where they came from. */
const HAND_RULE = 'hand-written';

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
  /** The rule name the roster gave this file, so a fault quotes the name the data states. */
  readonly rule: string;
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
  /** What the roster states about this path and value, which the run reads back out of the bytes before believing. */
  readonly statedInPath: boolean;
}

/** One entry as the roster states it, with its place in the file beside it for the refusal to name. */
interface RosterEntry {
  readonly index: number;
  readonly path: string;
  readonly description: string;
  readonly rule: string;
  readonly reason: string;
  readonly shape: string | undefined;
  readonly value: string | undefined;
  readonly statedInPath: boolean | undefined;
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

/**
 * The closed vocabulary: every rule name a roster may state, beside the arithmetic that earns it. A name missing
 * here is a refusal rather than a default, and this map is the list a refusal prints, so the roster never keeps a
 * second copy of it to drift from.
 */
const RULES: { readonly [name: string]: (text: string) => readonly Address[] } = {
  'epoch-public-half': epochAddresses,
  'capture-record-key': captureAddresses,
  'import-envelope-key': importAddresses,
};

/** The fields one roster entry may state, so a key spelled wrong is named rather than read as an absent one. */
const ENTRY_FIELDS = ['path', 'description', 'rule', 'reason', 'shape', 'value', 'statedInPath'];

/** What one roster entry yields: the block its rule earns, or the fault saying why it earns nothing. */
interface Earned {
  readonly derived: readonly DerivedFile[];
  readonly hand: readonly HandBlock[];
  readonly faults: readonly string[];
}

/** How the run names one entry: the roster it came from, its place in it, and the path it states. */
function nameOf(entry: RosterEntry): string {
  return `${ROSTER_PATH} entry ${String(entry.index)} at ${entry.path}`;
}

/**
 * One entry of the roster, read field by field. Every field the entry states that is not on the known list, and
 * every field a known type could not carry, comes back as a fault: the roster is a permission-bearing input, so
 * a run that guessed at a shape it did not recognise would be granting an exemption nobody wrote.
 */
function readEntry(index: number, raw: unknown): { readonly entry: RosterEntry | undefined; readonly fault: string } {
  const tag = `${ROSTER_PATH} entry ${String(index)}`;
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return {
      entry: undefined,
      fault: `${tag}: an entry has to be an object stating path, description, rule and reason`,
    };
  }
  const source = raw as { readonly [key: string]: unknown };
  const faults: string[] = [];
  const unknown = Object.keys(source).filter((key) => !ENTRY_FIELDS.includes(key));
  if (unknown.length > 0) {
    faults.push(`${tag}: states ${unknown.join(', ')}, which no rule reads. The fields are ${ENTRY_FIELDS.join(', ')}`);
  }
  const text = (field: string): string | undefined => {
    const stated = source[field];
    if (stated === undefined) {
      faults.push(`${tag}: states no ${field}`);
      return undefined;
    }
    if (typeof stated !== 'string' || stated === '') {
      faults.push(`${tag}: ${field} is not a string`);
      return undefined;
    }
    return stated;
  };
  const optionalText = (field: string): string | undefined => {
    if (source[field] === undefined) return undefined;
    return text(field);
  };
  const flag = (field: string): boolean | undefined => {
    const stated = source[field];
    if (stated === undefined) return undefined;
    if (typeof stated !== 'boolean') {
      faults.push(`${tag}: ${field} is not a boolean`);
      return undefined;
    }
    return stated;
  };

  const path = text('path');
  const description = text('description');
  const rule = text('rule');
  const reason = text('reason');
  if (path === undefined || description === undefined || rule === undefined || reason === undefined) {
    return { entry: undefined, fault: faults.join('; ') };
  }
  const entry: RosterEntry = {
    index,
    path,
    description,
    rule,
    reason,
    shape: optionalText('shape'),
    value: optionalText('value'),
    statedInPath: flag('statedInPath'),
  };
  if (faults.length > 0) return { entry: undefined, fault: faults.join('; ') };
  return { entry, fault: '' };
}

/** The roster at the scanned root, or the fault saying the root carries none and nothing was read. */
function readRoster(root: string): { readonly entries: readonly RosterEntry[]; readonly faults: readonly string[] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(join(root, ROSTER_PATH), 'utf8'));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      entries: [],
      faults: [`${ROSTER_PATH}: the roster this config is written from is unreadable here: ${reason}`],
    };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return {
      entries: [],
      faults: [`${ROSTER_PATH}: the roster has to be one object stating version, description and entries`],
    };
  }
  const source = parsed as { readonly [key: string]: unknown };
  const faults: string[] = [];
  const unknown = Object.keys(source).filter((key) => !['version', 'description', 'entries'].includes(key));
  if (unknown.length > 0) {
    faults.push(`${ROSTER_PATH}: states ${unknown.join(', ')}, which no rule reads`);
  }
  if (source['version'] !== ROSTER_VERSION) {
    faults.push(
      `${ROSTER_PATH}: states version ${String(source['version'])}, and this script reads version ` +
        `${String(ROSTER_VERSION)} of it`,
    );
  }
  const description = source['description'];
  if (typeof description !== 'string' || description === '') {
    faults.push(`${ROSTER_PATH}: states no description of what the roster is for`);
  }
  const raw = source['entries'];
  if (!Array.isArray(raw) || raw.length === 0) {
    faults.push(`${ROSTER_PATH}: states no entries, so no exemption would be earned`);
    return { entries: [], faults };
  }
  const entries: RosterEntry[] = [];
  for (const [index, one] of raw.entries()) {
    const read = readEntry(index, one);
    if (read.entry !== undefined) entries.push(read.entry);
    else faults.push(read.fault);
  }
  return { entries, faults };
}

/**
 * The roster read as blocks: the entries whose rule the script answers, the entries that state their own bytes,
 * and the faults. An entry that earns nothing is left out of both lists and named in the faults, so a run whose
 * roster is unreadable refuses rather than rendering a config with a hole where the entry sat.
 */
function earn(entries: readonly RosterEntry[], root: string): Earned {
  const derived: DerivedFile[] = [];
  const hand: HandBlock[] = [];
  const faults: string[] = [];
  for (const entry of entries) {
    const tag = nameOf(entry);
    if (!existsSync(join(root, entry.path))) {
      faults.push(`${tag}: the path it names is absent from this root, so nothing here can be read at it`);
      continue;
    }
    if (entry.rule === HAND_RULE) {
      if (entry.value === undefined) {
        faults.push(`${tag}: the ${HAND_RULE} class exempts the value the entry states, and it states none`);
        continue;
      }
      if (entry.statedInPath === undefined) {
        faults.push(
          `${tag}: a ${HAND_RULE} entry has to state statedInPath, whether a line of this path still carries the value`,
        );
        continue;
      }
      if (entry.shape !== undefined) {
        faults.push(`${tag}: ${HAND_RULE} recomputes no candidate, so the entry has to state no shape`);
        continue;
      }
      hand.push({
        path: entry.path,
        value: entry.value,
        description: entry.description,
        reason: [entry.reason],
        statedInPath: entry.statedInPath,
      });
      continue;
    }
    const address = RULES[entry.rule];
    if (address === undefined) {
      faults.push(
        `${tag}: names the rule ${entry.rule}, which no implementation answers. The rules this script reads are ` +
          [...Object.keys(RULES), HAND_RULE].join(', ') +
          '. A rule that cannot be named stays in the script; the roster is data, not a program.',
      );
      continue;
    }
    if (entry.shape === undefined) {
      faults.push(`${tag}: rule ${entry.rule} reads candidates at a shape, and the entry states none`);
      continue;
    }
    if (entry.value !== undefined || entry.statedInPath !== undefined) {
      faults.push(
        `${tag}: rule ${entry.rule} recomputes every value it admits, so the entry has to state no value and no ` +
          'statedInPath',
      );
      continue;
    }
    try {
      new RegExp(entry.shape, 'gu');
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      faults.push(`${tag}: the shape it states is not a pattern the scan can read: ${reason}`);
      continue;
    }
    derived.push({
      path: entry.path,
      description: entry.description,
      rule: entry.rule,
      pattern: entry.shape,
      reason: [entry.reason],
      addresses: address,
    });
  }
  return { derived, hand, faults };
}

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
  /** Set when the rule could not run at all over this file, or ran and admitted nothing the file states. */
  readonly fault: string | undefined;
}

function derive(file: DerivedFile, text: string): Derivation {
  const empty = { file, admitted: [], refused: [], unquoted: [], occurrences: 0 } as const;
  const stated = candidatesAt(text, file.pattern);
  let recomputed: readonly Address[];
  try {
    recomputed = file.addresses(text);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { ...empty, fault: `${file.path}: rule ${file.rule} does not run over this file: ${reason}` };
  }
  const addresses = new Map(recomputed.map((one) => [one.value, one]));
  const admitted: AdmittedValue[] = [];
  const refused: Candidate[] = [];
  for (const candidate of stated.at) {
    const address = addresses.get(candidate.value);
    if (address === undefined) refused.push(candidate);
    else admitted.push({ value: candidate.value, line: candidate.line, witness: address.witness });
  }
  const quoted = new Set(stated.at.map((one) => one.value));
  const fault =
    admitted.length === 0 && refused.length === 0
      ? `${file.path}: rule ${file.rule} admits no value at the shape ${ROSTER_PATH} states, so a block over this` +
        ' path would name nothing and exempt nothing with it'
      : undefined;
  return {
    ...empty,
    admitted: admitted.sort((a, b) => (a.value < b.value ? -1 : 1)),
    refused,
    unquoted: [...addresses.values()].filter((one) => !quoted.has(one.value)),
    occurrences: stated.occurrences,
    fault,
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
    'published, and the run prints whose bytes; a value with no address to name is declared hand-written in',
    '`scan-allowlist.json`, where it has to state what it is and where its bytes come from before it exempts',
    'anything. A scan run with `--redact` never prints the value it found, so no line here is authored out of a log.',
  ],
];

/** The config, as one string, derived from the roster at the root and the bytes the root carries. */
function renderScanConfig(
  root: string,
  derived: readonly DerivedFile[],
  handBlocks: readonly HandBlock[],
): { readonly text: string; readonly derivations: readonly Derivation[] } {
  const derivations = derived.map((file) => derive(file, readFileSync(join(root, file.path), 'utf8')));
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

  for (const hand of handBlocks) {
    lines.push(...comment([[...hand.reason]]));
    lines.push('');
    lines.push(...block(hand.description, [hand.value], hand.path));
    lines.push('');
  }

  return { text: `${lines.join('\n').replace(/\n+$/u, '\n')}\n`, derivations };
}

/** Where a hand-written value sits in the file its block names, read out of that file rather than assumed. */
function stateOf(hand: HandBlock, root: string): { readonly statement: string; readonly statedAt: number | undefined } {
  const text = readFileSync(join(root, hand.path), 'utf8');
  const found = text.split('\n').findIndex((each) => each.includes(hand.value));
  const statedAt = found === -1 ? undefined : found + 1;
  const statement =
    statedAt === undefined
      ? `${hand.path}: hand-written, and no line of this path states the value now, so the block answers for the history`
      : `${hand.path}: hand-written, value stated at line ${String(statedAt)} of this path`;
  return { statement, statedAt };
}

/** What the run says about the tree it read, and every candidate or entry it could not account for. */
function report(
  root: string,
  derivations: readonly Derivation[],
  handBlocks: readonly HandBlock[],
): readonly string[] {
  const findings: string[] = [];
  for (const one of derivations) {
    console.log(
      `${one.file.path}: ${String(one.admitted.length)} value(s) admitted over ${String(one.occurrences)} stated` +
        ` occurrence(s); ${String(one.unquoted.length)} recomputed digest(s) reach no shape the scan reads`,
    );
    if (one.fault !== undefined) {
      console.error(`  ${ROSTER_PATH}: ${one.fault}`);
      findings.push(one.fault);
    }
    for (const each of one.admitted) console.log(`  line ${String(each.line)} admitted: sha256 of ${each.witness}`);
    for (const each of one.unquoted) console.log(`  no block written: sha256 of ${each.witness}`);
    for (const each of one.refused) {
      console.error(
        `  ${one.file.path} line ${String(each.line)} refused: the file states a value where the scan reads a` +
          ' candidate, and no bytes this tree carries are the address of it',
      );
      findings.push(`${one.file.path} line ${String(each.line)}`);
    }
  }
  for (const hand of handBlocks) {
    const state = stateOf(hand, root);
    if ((state.statedAt !== undefined) === hand.statedInPath) {
      console.log(state.statement);
      continue;
    }
    const fault =
      hand.statedInPath
        ? `${hand.path}: ${ROSTER_PATH} states that a line of this path carries the hand-written value, and none` +
          ' does, so the block would exempt bytes this tree no longer holds'
        : `${hand.path}: ${ROSTER_PATH} states that no line of this path carries the hand-written value, and line` +
          ` ${String(state.statedAt)} does, so the entry describes an older tree than this one`;
    console.error(`  ${fault}`);
    findings.push(fault);
  }
  return findings;
}

const rootArgument = process.argv.indexOf('--root');
const ROOT = rootArgument === -1 ? DEFAULT_ROOT : resolve(process.argv[rootArgument + 1] ?? DEFAULT_ROOT);

const roster = readRoster(ROOT);
for (const fault of roster.faults) console.error(fault);
const earned = earn(roster.entries, ROOT);
for (const fault of earned.faults) console.error(fault);
const rendered = renderScanConfig(ROOT, earned.derived, earned.hand);
const findings = [...roster.faults, ...earned.faults, ...report(ROOT, rendered.derivations, earned.hand)];
const candidates = rendered.derivations.reduce((total, one) => total + one.refused.length, 0);

if (candidates > 0) {
  console.error(
    `refused: ${String(candidates)} unexplained candidate(s), so nothing was written. An exemption is earned by` +
      ' the bytes behind the value, not by the value.',
  );
}
if (findings.length > candidates) {
  console.error(
    `refused: ${String(findings.length - candidates)} ${ROSTER_PATH} fault(s), so nothing was written. The script` +
      ' keeps the arithmetic; the roster states what to earn, and an entry the bytes do not answer earns nothing.',
  );
}
if (findings.length > 0) process.exit(1);

writeFileSync(join(ROOT, '.gitleaks.toml'), rendered.text, 'utf8');
console.log(`wrote ${join(ROOT, '.gitleaks.toml')}`);
