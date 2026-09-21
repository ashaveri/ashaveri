import { describe, expect, it } from 'vitest';
import { readSourceFile } from './doc-contract.js';

/**
 * `24.21.0` is written in four places: `.nvmrc`, the `engines.node` floor in the root manifest, and the
 * two `FROM node:` tags in `enclave/Dockerfile`. A job installs the first and reads the second, but
 * nothing here builds the Dockerfile, so a bump that moved `.nvmrc` and left an image tag behind landed
 * with the image compiled on a Node no run in this repository has ever used. This file is what catches
 * that, and it names the file and the value that disagree rather than leaving someone to diff four.
 *
 * The version comes out of `.nvmrc` and every other copy is measured against it, so this test holds no
 * copy of `24.21.0` of its own: a fifth place to forget would pass on its own answer.
 *
 * `engines.node` is compared as a parsed range rather than as a string, because a range is what it
 * declares. `>=24.21.0 <25`, `>= 24.21.0 <25` and `>=24.21.0 <25.0.0` state one promise, and matching the
 * text would read a re-spacing as a disagreement while missing a floor quietly widened to `>=24.0.0`. Two
 * things follow from parsing instead. Nothing in this package's dependency tree can parse a range:
 * `semver` sits in the store several links deep, unreachable from a test here and with no types
 * installed, so the comparators are read below rather than a package added for one assertion. And the
 * reader is deliberately narrow, accepting only a whitespace-separated list of `>=`, `>`, `<=` and `<`
 * comparators, so a range in any other form is reported rather than read as agreement.
 *
 * Admitting the pin is not by itself the check, either. `>=24.21.0 <25` admits `24.22.0`, so a range can
 * be satisfied by a bumped `.nvmrc` while still naming the release before it: the floor has to be the pin.
 */

/** Repo-relative, because that is the spelling a failure message has to be readable in. */
const NVMRC = '.nvmrc';
const MANIFEST = 'package.json';
const DOCKERFILE = 'enclave/Dockerfile';

/** A workspace file, spelled the way the sibling document tests spell them. */
function repoFile(file: string): string {
  return readSourceFile(`../../../${file}`);
}

interface Version {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  /** As written in the file, so a message can quote the value rather than a reconstruction of it. */
  readonly text: string;
}

function parseVersion(text: string, where: string): Version {
  // The pattern carries exactly three capture groups, so each is present in every match it yields.
  const found = /^(\d+)\.(\d+)\.(\d+)$/u.exec(text);
  if (found === null) {
    throw new Error(`${where} states ${text}, which is not an exact X.Y.Z version`);
  }
  return { major: Number(found[1]), minor: Number(found[2]), patch: Number(found[3]), text };
}

/** Negative below, zero equal, positive above. */
function compare(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

type Operator = '>=' | '>' | '<=' | '<';
interface Comparator {
  readonly op: Operator;
  readonly version: Version;
}

/** What each operator asks of the ordering between a version and its bound. */
const HOLDS: Record<Operator, (order: number) => boolean> = {
  '>=': (order) => order >= 0,
  '>': (order) => order > 0,
  '<=': (order) => order <= 0,
  '<': (order) => order < 0,
};

/**
 * The comparators of a declared range. A short bound (`<25`) is filled out to `<25.0.0`, which is what a
 * range means by it.
 */
function parseRange(range: string, where: string): Comparator[] {
  const unreadable =
    `${where} declares "${range}", which cannot be read here: this file understands a `
    + 'whitespace-separated list of >=, >, <= and < comparators with numeric versions, and nothing else';
  const comparators: Comparator[] = [];
  for (const token of range.trim().split(/\s+/u)) {
    const found = /^(>=|<=|>|<)(\d+(?:\.\d+){0,2})$/u.exec(token);
    const op = found?.[1];
    const stated = found?.[2];
    if (op !== '>=' && op !== '>' && op !== '<=' && op !== '<') throw new Error(unreadable);
    if (stated === undefined) throw new Error(unreadable);
    const [major = '0', minor = '0', patch = '0'] = stated.split('.');
    comparators.push({ op, version: parseVersion(`${major}.${minor}.${patch}`, `${where} comparator ${token}`) });
  }
  if (comparators.length === 0) throw new Error(unreadable);
  return comparators;
}

function admitted(version: Version, comparators: Comparator[]): boolean {
  return comparators.every((comparator) => HOLDS[comparator.op](compare(version, comparator.version)));
}

/** The lowest version a range admits: the floor a pin has to sit on exactly. */
function floorOf(comparators: Comparator[]): Version {
  const lower = comparators.filter((c) => c.op === '>=' || c.op === '>');
  const floor = lower.reduce<Version | undefined>(
    (highest, c) => (highest === undefined || compare(c.version, highest) > 0 ? c.version : highest),
    undefined,
  );
  if (floor === undefined) {
    throw new Error(`${MANIFEST} engines.node sets no lower bound, so it admits every release`);
  }
  return floor;
}

/** One release below a version: a patch down, or a minor down where the patch is already zero. */
function oneBelow(version: Version): Version {
  const below =
    version.patch > 0
      ? { major: version.major, minor: version.minor, patch: version.patch - 1 }
      : version.minor > 0
        ? { major: version.major, minor: version.minor - 1, patch: 0 }
        : { major: version.major - 1, minor: 0, patch: 0 };
  return { ...below, text: `${below.major}.${below.minor}.${below.patch}` };
}

/** The version a `node:<tag>` base image names, with the suite suffix taken off. */
function tagVersion(reference: string): Version {
  const tag = reference.slice('node:'.length);
  const suffix = tag.indexOf('-');
  return parseVersion(suffix < 0 ? tag : tag.slice(0, suffix), `${DOCKERFILE} base image ${reference}`);
}

/** Every `FROM node:` line in the Dockerfile, so a stage added later cannot fall outside this check. */
function nodeBaseImages(): Array<{ readonly line: string; readonly reference: string }> {
  const images: Array<{ readonly line: string; readonly reference: string }> = [];
  for (const line of repoFile(DOCKERFILE).split('\n')) {
    const from = /^\s*FROM\s+(node:\S+)(?:\s+AS\s+\S+)?\s*$/iu.exec(line);
    const reference = from?.[1];
    if (reference !== undefined) images.push({ line: line.trim(), reference });
  }
  if (images.length === 0) {
    throw new Error(`${DOCKERFILE} names no node: base image, so nothing there is held to ${NVMRC}`);
  }
  return images;
}

/** `engines.node` from the root manifest, or the reason there is no floor to read. */
function declaredRange(): string {
  const manifest = JSON.parse(repoFile(MANIFEST)) as { engines?: { node?: string } };
  const range = manifest.engines?.node;
  if (range === undefined || range.trim().length === 0) {
    throw new Error(`${MANIFEST} declares no engines.node, so nothing there is held to ${NVMRC}`);
  }
  return range.trim();
}

/** The one value `.nvmrc` holds, or the reason there is nothing to hold the copies to. */
function statedPin(): string {
  const values = repoFile(NVMRC)
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (values.length !== 1) {
    throw new Error(`${NVMRC} states ${values.join(', ')}, which is not the one version the copies are held to`);
  }
  const [value] = values;
  if (value === undefined) throw new Error(`${NVMRC} states nothing, so there is no version to hold the copies to`);
  return value;
}

function pinned(): Version {
  return parseVersion(statedPin(), NVMRC);
}

describe('the copies of the pinned Node version', () => {
  it('names one exact release in .nvmrc to hold the others to', () => {
    const stated = statedPin();
    expect(stated, `${NVMRC} states ${stated}, which is not an exact release the other copies can sit on`).toMatch(
      /^\d+\.\d+\.\d+$/u,
    );
  });

  it('declares that release as the engines.node floor and admits nothing below it', () => {
    const pin = pinned();
    const range = declaredRange();
    const comparators = parseRange(range, `${MANIFEST} engines.node`);
    const floor = floorOf(comparators);
    expect(
      compare(floor, pin),
      `${MANIFEST} engines.node is "${range}", whose floor is ${floor.text}, but ${NVMRC} pins ${pin.text}`,
    ).toBe(0);
    expect(
      admitted(pin, comparators),
      `${MANIFEST} engines.node is "${range}", which does not admit ${pin.text}, the version ${NVMRC} pins`,
    ).toBe(true);
    const below = oneBelow(pin);
    expect(
      admitted(below, comparators),
      `${MANIFEST} engines.node is "${range}", which admits ${below.text}, a release below the pinned ${pin.text}`,
    ).toBe(false);
  });

  it('names that release in every node: base image of enclave/Dockerfile', () => {
    const pin = pinned();
    const disagreed: string[] = [];
    for (const image of nodeBaseImages()) {
      const named = tagVersion(image.reference);
      if (compare(named, pin) !== 0) {
        disagreed.push(`${DOCKERFILE} has ${image.line}, naming Node ${named.text} while ${NVMRC} pins ${pin.text}`);
      }
    }
    expect(disagreed.length, disagreed.join('\n')).toBe(0);
  });
});
