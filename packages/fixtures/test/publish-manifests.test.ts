import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readSourceFile, spelledNumber } from './doc-contract.js';

/**
 * What a publish reads. `@ashaveri/*` packages reach a registry through
 * `.github/workflows/publish.yml`, and every field this file names is a field that command reads off a
 * manifest: the version a tarball is filed under, the `files` list that decides what a stranger receives,
 * the `publishConfig.access` that decides whether that stranger can install it at all, and the sibling
 * ranges that decide whether the package they install resolves anything. A manifest with those fields
 * wrong is not a build failure. It is a published artifact that cannot be taken back.
 *
 * So the checks here are the ones a registry would otherwise be the first to make:
 *
 *   One version, everywhere. All seven manifests state one version, stated as an exact release rather
 *   than a range, and the sentence the public README says about that version says the same number.
 *
 *   The metadata a publish reads, and nothing invented beside it. `repository.directory` is the path the
 *   manifest actually sits at, and `bugs.url` and `homepage` are read off `repository.url` rather than
 *   typed again where a typo would survive review.
 *
 *   The `files` list covers every entry point. `main`, `types`, `bin` and every `exports` target live in
 *   a directory the manifest said to ship. This is the tarball's property and not the workspace's: a
 *   workspace resolves a sibling through a link to its directory, where a consumer gets only the bytes
 *   the `files` list chose.
 *
 *   The publish set is the set with no `private` flag, in an order a consumer can install. The workflow
 *   names packages, the manifests say which are publishable and which depend on which, and this file
 *   makes the two answer to each other, because a package added to the workspace, or moved to public,
 *   without an entry in that list would be silently unpublished rather than loudly wrong.
 *
 * Two facts are stated here rather than checked, because a check would restate the implementation rather
 * pin a contract. The `private` flag is the only thing in a manifest standing between a package and a
 * publish: `publishConfig.access` is inert under it, which is what lets the gateway carry both today. And
 * npm ships a package's own license text and not the repository's, so where a package directory holds no
 * license file this file holds that package's declared id against the repository's own license, which is
 * the arrangement today and is a statement about intent rather than about the bytes in a tarball.
 */

/** Repo-relative spellings, because that is what a failure message has to be readable in. */
const WORKSPACE_ROOT = '../../../';
const WORKFLOW = 'publish.yml';
const WORKFLOW_PATH = '.github/workflows/publish.yml';
const README = 'README.md';
const ROOT_LICENSE = 'LICENSE';

/** The two places a package sits in this workspace: one directory each, plus the gateway. */
const PACKAGE_PARENT = '../../';
const GATEWAY_DIR = 'gateway';

const SCOPE = '@ashaveri/';

interface Manifest {
  readonly dir: string;
  readonly name: string;
  readonly version: string;
  readonly fields: Record<string, unknown>;
}

/** The fields this file reads, taken as they come so a wrong type is reported rather than coerced. */
function field(manifest: Manifest, key: string): unknown {
  return manifest.fields[key];
}

function stringField(manifest: Manifest, key: string): string {
  const value = field(manifest, key);
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${manifest.dir}/package.json states no ${key} this file can read`);
  }
  return value;
}

function objectField(manifest: Manifest, key: string): Record<string, unknown> {
  const value = field(manifest, key);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${manifest.dir}/package.json has no ${key} object`);
  }
  return value as Record<string, unknown>;
}

/** Every `@ashaveri` manifest in the workspace, found by walking it rather than by a list kept here. */
let workspaceManifests: Manifest[] | undefined;

function manifests(): Manifest[] {
  if (workspaceManifests !== undefined) return workspaceManifests;
  const parent = fileURLToPath(new URL(PACKAGE_PARENT, import.meta.url));
  const dirs = readdirSync(parent, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `packages/${entry.name}`)
    .concat(GATEWAY_DIR)
    .filter((dir) => existsRepoFile(`${dir}/package.json`));
  const found: Manifest[] = [];
  for (const dir of dirs) {
    const raw = JSON.parse(readRepoFile(`${dir}/package.json`)) as Record<string, unknown>;
    const name = raw['name'];
    if (typeof name !== 'string' || !name.startsWith(SCOPE)) continue;
    const version = raw['version'];
    if (typeof version !== 'string') {
      throw new Error(`${dir}/package.json names ${name} with no version string`);
    }
    found.push({ dir, name, version, fields: raw });
  }
  if (found.length === 0) throw new Error(`no ${SCOPE}* manifest was found in the workspace`);
  workspaceManifests = found.sort((a, b) => a.name.localeCompare(b.name));
  return workspaceManifests;
}

function existsRepoFile(relative: string): boolean {
  return existsSync(fileURLToPath(new URL(`${WORKSPACE_ROOT}${relative}`, import.meta.url)));
}

function readRepoFile(relative: string): string {
  return readSourceFile(`${WORKSPACE_ROOT}${relative}`);
}

/**
 * The publishable set, read the way a registry reads it. Only `private: true` holds a package back, so a
 * manifest spelling the flag `false` belongs here whether or not this workspace ever writes it that way,
 * and the set test below is then the second place that disagreement lands rather than the only one.
 */
function publishable(): Manifest[] {
  return manifests().filter((manifest) => field(manifest, 'private') !== true);
}

/**
 * The package directories `publish.yml` lists in the order it publishes them, read out of the shell
 * array its publish step builds.
 */
function workflowOrder(): string[] {
  const lines = readRepoFile(WORKFLOW_PATH).split('\n');
  const start = lines.findIndex((line) => /^\s*order=\($/u.test(line));
  if (start < 0) throw new Error(`${WORKFLOW} builds no publish order this file can read`);
  const order: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\s*\)/u.test(line)) break;
    const entry = /^\s*([a-zA-Z0-9_./-]+)\s*$/u.exec(line);
    const dir = entry?.[1];
    if (dir !== undefined) order.push(dir);
  }
  if (order.length === 0) throw new Error(`the publish order in ${WORKFLOW} is empty`);
  return order;
}

/** The trigger keys written directly under the workflow's `on:` block. */
function workflowTriggers(): string[] {
  const lines = readRepoFile(WORKFLOW_PATH).split('\n');
  const at = lines.findIndex((line) => line === 'on:');
  if (at < 0) throw new Error(`${WORKFLOW} declares no top-level on: block`);
  const found: string[] = [];
  for (const line of lines.slice(at + 1)) {
    if (line.trim().length > 0 && !/^\s/u.test(line)) break;
    const key = /^\s\s([a-z_]+):/u.exec(line);
    const name = key?.[1];
    if (name !== undefined) found.push(name);
  }
  return found;
}

/** One-line labels of the workflow's steps, in the order they run. */
function workflowSteps(): string[] {
  const steps: string[] = [];
  for (const line of readRepoFile(WORKFLOW_PATH).split('\n')) {
    const step = /^\s{6}- (?:name|uses|run): (.+)$/u.exec(line);
    const label = step?.[1];
    if (label !== undefined) steps.push(label.trim());
  }
  if (steps.length === 0) throw new Error(`${WORKFLOW} has no readable steps`);
  return steps;
}

function indexOfStep(holding: string): number {
  const at = workflowSteps().findIndex((step) => step.includes(holding));
  if (at < 0) throw new Error(`${WORKFLOW} has no step labelled with "${holding}"`);
  return at;
}

/** Every path an entry point names, with the `./` a manifest spells it with taken off. */
function entryPoints(manifest: Manifest): string[] {
  const listed: string[] = [];
  for (const key of ['main', 'types']) {
    const value = field(manifest, key);
    if (typeof value === 'string') listed.push(value);
  }
  const bin = field(manifest, 'bin');
  if (typeof bin === 'string') listed.push(bin);
  else if (typeof bin === 'object' && bin !== null) {
    for (const value of Object.values(bin as Record<string, unknown>)) {
      if (typeof value === 'string') listed.push(value);
    }
  }
  // `exports` nests, so the targets are collected by walking rather than by reading one shape.
  const walk = (value: unknown): void => {
    if (typeof value === 'string') {
      listed.push(value);
      return;
    }
    if (typeof value === 'object' && value !== null) {
      for (const nested of Object.values(value as Record<string, unknown>)) walk(nested);
    }
  };
  walk(field(manifest, 'exports'));
  return listed;
}

/** The license text each package's declared id promises, per package where it has one. */
const LICENSE_MARKERS: Record<string, string> = {
  'Apache-2.0': 'Apache License',
  'CC0-1.0': 'CC0 1.0 Universal',
};

function licenseFileIn(dir: string): string | undefined {
  const entries = readdirSync(fileURLToPath(new URL(`${WORKSPACE_ROOT}${dir}`, import.meta.url)));
  const hit = entries.find((entry) => /^(LICEN[CS]E(\.md)?|COPYING)$/iu.test(entry));
  return hit;
}

describe('the manifests a publish reads', () => {
  it('states one exact version in every scoped manifest', () => {
    const stated = new Map<string, string[]>();
    for (const manifest of manifests()) {
      expect(
        /^\d+\.\d+\.\d+$/u.test(manifest.version),
        `${manifest.dir}/package.json states version ${manifest.version}, which is not an exact release`,
      ).toBe(true);
      stated.set(manifest.version, [...(stated.get(manifest.version) ?? []), manifest.name]);
    }
    const versions = [...stated.keys()];
    expect(versions.length, `the scoped manifests state ${versions.join(' and ')}, which is not one version`).toBe(1);
  });

  it('carries the repository, its issues address and a homepage read off the same address', () => {
    for (const manifest of manifests()) {
      const repository = objectField(manifest, 'repository');
      expect(repository['type'], `${manifest.dir} repository.type is not git`).toBe('git');
      const url = repository['url'];
      expect(typeof url, `${manifest.dir} states no repository.url`).toBe('string');
      const base = (url as string).replace(/^git\+/u, '').replace(/\.git$/u, '');
      expect(
        base.startsWith('https://github.com/'),
        `${manifest.dir} repository.url is ${String(url)}, which names no such address to read a home from`,
      ).toBe(true);
      const bugs = objectField(manifest, 'bugs');
      expect(
        bugs['url'],
        `${manifest.dir} bugs.url is ${String(bugs['url'])}, not ${base}/issues, which is the address its own repository.url points at`,
      ).toBe(`${base}/issues`);
      const homepage = stringField(manifest, 'homepage');
      expect(
        homepage.startsWith(base),
        `${manifest.dir} homepage is ${homepage}, which sits outside ${base}, the repository it declares itself part of`,
      ).toBe(true);
    }
  });

  it('names the directory each package sits in', () => {
    for (const manifest of manifests()) {
      const directory = objectField(manifest, 'repository')['directory'];
      expect(
        directory,
        `${manifest.dir}/package.json states repository.directory as ${String(directory)}`,
      ).toBe(manifest.dir);
    }
  });

  it('declares the access a scoped package needs or arrives restricted', () => {
    for (const manifest of manifests()) {
      expect(
        objectField(manifest, 'publishConfig')['access'],
        `${manifest.dir} would be published ${String(objectField(manifest, 'publishConfig')['access'])}`,
      ).toBe('public');
    }
  });

  it('keeps the private flag as the only statement of publishability', () => {
    const held: string[] = [];
    for (const manifest of manifests()) {
      const value = field(manifest, 'private');
      // `private: false` and no `private` member mean one thing to a registry, and a workspace that
      // writes both says the same fact in two places that can later disagree.
      expect(
        value === undefined || value === true,
        `${manifest.dir} states private as ${JSON.stringify(value)}; a manifest here either carries the flag or omits it`,
      ).toBe(true);
      if (value === true) held.push(manifest.name);
    }
    expect(
      held,
      `the packages held back from a publish today are ${held.join(', ')}, which is the gateway and nothing else`,
    ).toEqual(['@ashaveri/signerd']);
  });

  it('ships the directory every entry point lives in', () => {
    for (const manifest of manifests()) {
      const files = field(manifest, 'files');
      expect(Array.isArray(files) && files.length > 0, `${manifest.dir} declares no files list`).toBe(true);
      const shipped = (files as unknown[]).map((entry) => String(entry).replace(/^\.\//u, ''));
      for (const target of entryPoints(manifest)) {
        const clean = target.replace(/^\.\//u, '');
        const top = clean.split('/')[0] ?? clean;
        // `package.json` is always shipped, and a bare file at the package root is shipped by naming it.
        if (clean === 'package.json') continue;
        expect(
          shipped.includes(top) || shipped.includes(clean),
          `${manifest.dir} points a consumer at ${target} while its files list (${shipped.join(', ')}) says to ship none of it`,
        ).toBe(true);
      }
    }
  });

  it('finds each built entry point where the manifest says it will be', () => {
    // A suite runs before a build as readily as after one, so this is asserted only where the output
    // is on disk: it checks that what the build emitted is where the manifest promises it, which is
    // the same promise a consumer of the tarball takes.
    const unbuilt = manifests().filter((manifest) => !existsRepoFile(`${manifest.dir}/dist`));
    if (unbuilt.length > 0) return;
    const missing: string[] = [];
    for (const manifest of manifests()) {
      for (const target of entryPoints(manifest)) {
        const path = `${manifest.dir}/${target.replace(/^\.\//u, '')}`;
        if (!existsRepoFile(path)) missing.push(`${manifest.name}: ${path}`);
      }
    }
    expect(missing.length, `built entry points the manifests point at but the build did not write:\n${missing.join('\n')}`).toBe(0);
  });

  it('links its siblings with the protocol that links them, not a range', () => {
    for (const manifest of manifests()) {
      for (const key of ['dependencies', 'devDependencies']) {
        const block = field(manifest, key);
        if (typeof block !== 'object' || block === null) continue;
        for (const [name, range] of Object.entries(block as Record<string, unknown>)) {
          if (!name.startsWith(SCOPE)) continue;
          expect(
            typeof range === 'string' && range.startsWith('workspace:'),
            `${manifest.dir} states ${key} ${name} as ${String(range)}: a semver range there would resolve against a registry that has no package under this scope yet, and the sibling would be linked from no workspace`,
          ).toBe(true);
        }
      }
    }
  });

  it('ships the license text its declared id promises', () => {
    for (const manifest of manifests()) {
      const license = stringField(manifest, 'license');
      const marker = LICENSE_MARKERS[license];
      if (marker === undefined) {
        throw new Error(`${manifest.dir} declares ${license}, which this file has no license text to compare it with`);
      }
      const local = licenseFileIn(manifest.dir);
      const relative = local === undefined ? ROOT_LICENSE : `${manifest.dir}/${local}`;
      expect(
        readRepoFile(relative).includes(marker),
        `${manifest.dir} declares ${license} while ${relative} carries no ${license} text`,
      ).toBe(true);
    }
  });
});

describe('the publish order against the manifests', () => {
  it('publishes exactly the packages that carry no private flag', () => {
    const order = workflowOrder();
    const listed = new Set(order);
    const expected = publishable().map((manifest) => manifest.dir);
    const missing = expected.filter((dir) => !listed.has(dir));
    const extra = order.filter((dir) => !expected.includes(dir));
    expect(
      [...missing, ...extra],
      `publish.yml names ${order.join(', ')}; the manifests with no private flag are ${expected.join(', ')}`,
    ).toEqual([]);
    expect(
      new Set(order).size,
      `publish.yml lists ${order.length} entries but only ${new Set(order).size} distinct packages`,
    ).toBe(order.length);
  });

  it('publishes each package after every sibling it depends on', () => {
    const order = workflowOrder();
    const position = new Map(order.map((dir, at) => [dir, at]));
    const wrong: string[] = [];
    for (const dir of order) {
      const manifest = manifests().find((candidate) => candidate.dir === dir);
      if (manifest === undefined) throw new Error(`publish.yml names ${dir}, which holds no scoped manifest`);
      const dependencies = objectField(manifest, 'dependencies');
      for (const [name, range] of Object.entries(dependencies)) {
        // A devDependency needs no sibling on a registry first: npm strips that block at publish, and
        // no consumer ever installs it. Only what a package ships to its users is ordered here.
        if (!name.startsWith(SCOPE) || !String(range).startsWith('workspace:')) continue;
        const dependency = manifests().find((candidate) => candidate.name === name);
        if (dependency === undefined) throw new Error(`${manifest.name} depends on ${name}, which is in no manifest`);
        const at = position.get(dependency.dir);
        if (at === undefined || at >= (position.get(dir) ?? -1)) {
          wrong.push(`${manifest.name} is published before ${name}, which it depends on`);
        }
      }
    }
    expect(wrong.length, wrong.join('\n')).toBe(0);
  });

  it('installs, builds and tests the tree before it publishes a line of it', () => {
    expect(
      indexOfStep('pnpm install') < indexOfStep('Build and test'),
      'publish.yml publishes from a tree it did not install, build and test in the same job',
    ).toBe(true);
    expect(
      indexOfStep('Build and test') < indexOfStep('Publish the packages'),
      'the publish step of publish.yml does not come after the build and test step',
    ).toBe(true);
  });

  it('publishes through provenance and access it states on the command', () => {
    const workflow = readRepoFile(WORKFLOW_PATH);
    expect(
      /npm publish .*--provenance.*--access public.*--no-git-tag-version/u.test(workflow),
      'publish.yml does not publish with --provenance, --access public and --no-git-tag-version',
    ).toBe(true);
  });

  it('has no trigger but the one a person pulls', () => {
    // The limit is the shape a trigger has to take to be a trigger at all: one written deeper than two
    // spaces under `on:` is not a GitHub event, and would fail on the runner rather than publish here.
    expect(workflowTriggers(), 'publish.yml declares triggers other than a manual dispatch').toEqual(['workflow_dispatch']);
  });

  it('holds no credential but the one the run mints', () => {
    const workflow = readRepoFile(WORKFLOW_PATH);
    expect(/secrets\./u.test(workflow), 'publish.yml reads a repository secret').toBe(false);
    expect(/_TOKEN\b/u.test(workflow), 'publish.yml names a token variable a long-lived credential would live in').toBe(false);
    const declared = /^permissions:\n((?: {2}[a-z-]+: \w+\n)+)/mu.exec(workflow)?.[1];
    if (declared === undefined) throw new Error('publish.yml declares no permissions block this file can read');
    const wanted = new Map(
      declared
        .trim()
        .split('\n')
        .map((line) => line.split(':'))
        .map(([key, value]) => [key?.trim() ?? '', value?.trim() ?? '']),
    );
    expect([...wanted.keys()].sort(), `publish.yml asks for ${[...wanted.keys()].join(', ')}`).toEqual([
      'contents',
      'id-token',
    ]);
    expect(wanted.get('contents'), 'a publish that rewrites its own tree is not the one this file describes').toBe('read');
    expect(wanted.get('id-token'), 'with no id token to trade, this workflow proves nothing about the bytes it uploads').toBe('write');
  });
});

describe('what the public README says about the same packages', () => {
  it('counts the publishable packages as the manifests do', () => {
    const sentence = /The (\w+) publishable packages are at `([^`]+)`/u.exec(readRepoFile(README));
    if (sentence === null) {
      throw new Error(`${README} no longer states how many publishable packages there are, so nothing holds that sentence`);
    }
    const word = sentence[1] ?? '';
    const stated = sentence[2] ?? '';
    expect(spelledNumber(word), `${README} says ${word} publishable packages; the manifests carry no private flag in ${publishable().length}`)
      .toBe(publishable().length);
    const [version] = manifests();
    if (version === undefined) throw new Error('no scoped manifest was found');
    expect(stated, `${README} states ${stated} while ${version.dir} states ${version.version}`).toBe(version.version);
  });
});
