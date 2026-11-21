import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  compareVersions,
  entryPoints,
  floorOf,
  isPublishable,
  PACKAGE_SCOPE,
  parseRange,
  readSourceFile,
  rangesAgree,
  scopedManifests,
  sectionBody,
  spelledNumber,
  tableRows,
  type Comparator,
  type PackageManifest,
} from './doc-contract.js';

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
 *   typed again where a typo would survive review. Every publishable manifest also declares a `prepack`
 *   that runs its own `build`, because a pack reads the directory on disk rather than the source beside
 *   it, and a stale one publishes as quietly as a fresh one.
 *
 *   The `files` list covers every entry point. `main`, `types`, `bin` and every `exports` target live in
 *   a directory the manifest said to ship. This is the tarball's property and not the workspace's: a
 *   workspace resolves a sibling through a link to its directory, where a consumer gets only the bytes
 *   the `files` list chose. A `bin` is read in both shapes a manifest may write it in, the map for several
 *   commands and the bare string for one, because the shorter of the two names a way in rather than none.
 *   The two fields a resolver reads before it reads any map are read from the fields too, and not only from
 *   the map's copy of the same paths, because five of the six publishable manifests state both and a reader
 *   that kept only the map would weigh one of the two statements and call that coverage.
 *
 *   Every publishable manifest states a Node floor, and the floor it states is the one the root manifest
 *   declares for this workspace. The range is read off that manifest rather than written out again here, so
 *   the six published copies and the workspace declaration cannot drift apart, and `pinned-node.test.ts`
 *   already holds the root range to the release `.nvmrc` names. The two are read with that file's reader and
 *   compared on the versions they admit rather than on their spelling, because a spacing is not a promise and
 *   a widened floor is one. The tolerance and the refusal are each held by a case rather than by this
 *   paragraph: one reads a manifest's range re-spaced and finds the same floor, and one hands the comparison
 *   ranges this tree does not ship and finds each of them reported by the name of the manifest that would
 *   state it.
 *
 *   The publish set is the set with no `private` flag, in an order a consumer can install. The workflow
 *   names packages, the manifests say which are publishable and which depend on which, and this file
 *   makes the two answer to each other, because a package added to the workspace, or moved to public,
 *   without an entry in that list would be silently unpublished rather than loudly wrong. Which manifest
 *   counts as one, and which paths a manifest names as a way into it, are read from `doc-contract.ts`:
 *   `installed-artifacts.test.ts` installs the set this rule picks out, and two copies of a rule drift
 *   apart long before either suite says so out loud. A name from the held-back set belongs in no field an
 *   installer reads, and in a development dependency only where this file lists that package beside it,
 *   because a pack rewrites a workspace range into an exact version in every block a manifest carries. That
 *   list and the paragraph of `docs/receipt-spec.md` stating the same position are compared by one case, which
 *   reads the clause enumerating them rather than the paragraph arguing them, since the document is what a reader
 *   trusts, two copies of one claim drift apart on their own schedule, and a package named further along in that
 *   paragraph is not a package the document says carries anything.
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
const ROOT_MANIFEST = 'package.json';

/** The two places a package sits in this workspace: one directory each, plus the gateway. */
const PACKAGE_PARENT = '../../';
const GATEWAY_DIR = 'gateway';

const SCOPE = PACKAGE_SCOPE;

/** One workspace manifest, as the shared reader returns it. */
type Manifest = PackageManifest;

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

/**
 * The names one dependency block declares, or nothing where the manifest carries no such block. A block is
 * read as a list of names rather than of ranges here because the question asked of it is who is named, and
 * the range beside a name is another case's business.
 */
function dependencyNames(manifest: Manifest, key: string): string[] {
  const block = field(manifest, key);
  if (typeof block !== 'object' || block === null || Array.isArray(block)) return [];
  return Object.keys(block as Record<string, unknown>);
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
  const found = scopedManifests(dirs.map((dir) => ({ dir, text: readRepoFile(`${dir}/package.json`) })));
  if (found.length === 0) throw new Error(`no ${SCOPE}* manifest was found in the workspace`);
  workspaceManifests = found;
  return found;
}

function existsRepoFile(relative: string): boolean {
  return existsSync(fileURLToPath(new URL(`${WORKSPACE_ROOT}${relative}`, import.meta.url)));
}

function readRepoFile(relative: string): string {
  return readSourceFile(`${WORKSPACE_ROOT}${relative}`);
}

/**
 * The publishable set, read the way a registry reads it: `isPublishable` in `doc-contract.ts` is the rule,
 * shared with the test that installs the set it picks out, so neither can drift into a different meaning
 * of the same sentence.
 */
function publishable(): Manifest[] {
  return manifests().filter((manifest) => isPublishable(manifest.fields));
}

/**
 * The directories a manifest's own entry points say its built output lives in, or the reason it names none.
 * A way in is written as a path into the tree the build writes, so the directory above it is where a pack
 * would find the bytes: read there rather than to one directory spelled out in this file, because a package
 * that moves its output would then be a package nothing weighs. That is not a tidiness argument. The case
 * below treats a publish set with no output anywhere as a suite that ran before the build, and a directory
 * named here rather than by the manifest turns every package into an unbuilt one, so the refusal that exists
 * to catch a half-built publish becomes a permanent skip.
 */
function outputDirs(manifest: Manifest): string[] {
  const targets = entryPoints(manifest.fields);
  if (targets.length === 0) {
    throw new Error(`${manifest.dir}/package.json names no entry point, so nothing here says where its build writes`);
  }
  const dirs: string[] = [];
  for (const target of targets) {
    const clean = target.replace(/^\.\//u, '');
    const at = clean.lastIndexOf('/');
    if (at < 0) {
      throw new Error(
        `${manifest.dir}/package.json names the entry point ${target} at the package root, so no directory ` +
          'says where its build wrote',
      );
    }
    dirs.push(clean.slice(0, at));
  }
  return [...new Set(dirs)].sort();
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

/** The `engines.node` a manifest states, as it is written, or nothing where it states none. */
function nodeRangeOf(manifest: Manifest): string | undefined {
  const engines = field(manifest, 'engines');
  const declared =
    typeof engines === 'object' && engines !== null && !Array.isArray(engines)
      ? (engines as Record<string, unknown>)['node']
      : undefined;
  return typeof declared === 'string' && declared.trim().length > 0 ? declared : undefined;
}

/**
 * The floor the workspace declares for itself, read off its own manifest rather than copied here. It is
 * handed to the range reader as written, because the comparison below is on what the two ranges admit and
 * not on how either of them is spaced.
 */
function rootEnginesRange(): string {
  const engines = (JSON.parse(readRepoFile(ROOT_MANIFEST)) as Record<string, unknown>)['engines'];
  if (typeof engines !== 'object' || engines === null || Array.isArray(engines)) {
    throw new Error(`${ROOT_MANIFEST} declares no engines object, so a package has no floor to state`);
  }
  const declared = (engines as Record<string, unknown>)['node'];
  if (typeof declared !== 'string' || declared.trim().length === 0) {
    throw new Error(`${ROOT_MANIFEST} declares no engines.node, so a package has no floor to state`);
  }
  return declared.trim();
}

/**
 * The same range with each operator set apart from its version by a space, which is one of the ways a
 * manifest may be written: npm reads `>= 26.13.0 < 27` as the promise `>=26.13.0 <27` makes, and an author
 * retyping a range in an editor that wraps the line produces the first out of the second. The reader takes
 * that space back out, so neither spelling is a floor moved, and the case below is what says so.
 */
function spacedOperators(range: string): string {
  return range.replace(/([<>]=?)[ \t]*/gu, '$1 ');
}

/** A package directory the tree does not hold, used by the cases that state a range nobody ships. */
const PLANTED_DIR = 'packages/planted';

/**
 * What one manifest's floor disagrees with the workspace's about, written as the line this file reports, or
 * nothing where the two state one promise. The check below reads every publishable manifest through this
 * function, and a case hands it a manifest the tree does not hold: a comparison only ever shown agreeing has
 * never been shown refusing, and the widened floor is the thing this field exists to catch. A range the
 * reader cannot read is left to throw, naming the manifest that states it, rather than turned into one line
 * among several: a range nobody can read states no promise to compare, so it may not be booked as either a
 * match or a mismatch.
 */
function floorDisagreement(
  dir: string,
  stated: string | undefined,
  declared: Comparator[],
  wanted: string,
): string | undefined {
  if (stated === undefined) {
    return `${dir} states engines.node as nothing, where ${ROOT_MANIFEST} states ${wanted}`;
  }
  if (!rangesAgree(parseRange(stated, `${dir} engines.node`), declared)) {
    return `${dir} states engines.node as ${stated}, which is not the promise ${ROOT_MANIFEST} states as ${wanted}`;
  }
  return undefined;
}

/**
 * The dependency fields npm reads when it installs a package. What sits in one of them has to resolve on a
 * registry, so a name this workspace holds back from a registry cannot appear in any of them.
 */
const CONSUMER_INSTALLED_FIELDS = ['dependencies', 'peerDependencies', 'optionalDependencies'];

/**
 * The private packages each publishable manifest is allowed to name as a development dependency, and nothing
 * else in this file. A private package has no tarball on a registry, so a name of one reaches a published
 * manifest only where no installer is asked to resolve it: three suites mint signing credentials through the
 * workspace signer, which is a decision those three manifests already make and `docs/receipt-spec.md` states.
 * Writing the three here is what turns a fourth package gaining the same dependency from drift into an edit
 * to this list, and an edit is a thing a reviewer sees.
 */
const PRIVATE_DEV_DEPENDENCIES: Record<string, readonly string[]> = {
  'packages/cli': ['@ashaveri/signerd'],
  'packages/fixtures': ['@ashaveri/signerd'],
  'packages/sdk': ['@ashaveri/signerd'],
};

/** The compatibility contract, read by the case that holds this list to the prose stating the same position. */
const RECEIPT_SPEC = 'docs/receipt-spec.md';

/** The sentence opening the paragraph of that document which states the position. */
const SPEC_POSITION_ANCHOR = 'publish a package name no registry serves';

/** The phrase the enumeration closes with, and so the end of the clause that lists the packages. */
const SPEC_LISTED_SET = 'each list';

/**
 * The clause that names the packages carrying a private development dependency: the text from the start of its
 * sentence to the phrase the sentence uses for the set. The rest of the paragraph argues why the name resolves
 * nowhere, points at the gateway by another route, and describes what this file checks, so a package named
 * there is not a package the document says carries anything. Reading the whole paragraph for scoped names turned
 * an incidental mention into a refusal that claimed that package carried a private devDependency.
 *
 * Two things this refuses rather than reads around. The phrase has to appear once, because two of them leave this
 * clause ending at whichever came first and the enumeration behind it unchecked. And the clause has to yield a
 * name, because a clause that yielded none would leave the comparison below with one direction to run.
 */
function specListingClause(paragraph: string): string {
  const found = [...paragraph.matchAll(new RegExp(SPEC_LISTED_SET, 'gu'))];
  if (found.length !== 1) {
    throw new Error(
      `"${SPEC_LISTED_SET}" appears ${String(found.length)} times in the paragraph of ${RECEIPT_SPEC} that states ` +
        'the position, and the clause listing the packages ends at exactly one of them',
    );
  }
  const at = found[0]?.index ?? -1;
  const boundary = paragraph.lastIndexOf('. ', at);
  if (boundary < 0) {
    throw new Error(`the paragraph of ${RECEIPT_SPEC} holding "${SPEC_LISTED_SET}" is not a sentence this can find the start of`);
  }
  const clause = paragraph.slice(boundary + 2, at);
  if (!new RegExp(`${SCOPE}[a-z0-9-]+`, 'u').test(clause)) {
    throw new Error(
      `the clause of ${RECEIPT_SPEC} that ends "${SPEC_LISTED_SET}" names no ${SCOPE} package, so the enumeration ` +
        'this compares against PRIVATE_DEV_DEPENDENCIES has no names in it: ' +
        JSON.stringify(clause.replace(/\s+/gu, ' ').slice(0, 120)),
    );
  }
  return clause;
}

/**
 * The paragraph naming the packages that carry a private development dependency, read out of the document
 * rather than restated here. The list above and the list in that paragraph are one claim written in two
 * places, and two copies of a claim drift: the case below compares them, and a paragraph this anchor does not
 * find exactly once is reported rather than passed over, because a document that states the position twice
 * leaves this case holding one copy of two, and one that states it nowhere leaves it comparing nothing.
 */
function specDevDependencyParagraph(): string {
  const found = readRepoFile(RECEIPT_SPEC)
    .split(/\n\n+/u)
    .filter((paragraph) => paragraph.includes(SPEC_POSITION_ANCHOR));
  if (found.length !== 1) {
    throw new Error(
      `"${SPEC_POSITION_ANCHOR}" opens ${String(found.length)} paragraphs of ${RECEIPT_SPEC}, and this case ` +
        'reads exactly one',
    );
  }
  return found[0] ?? '';
}

/**
 * Whether one `prepack` value runs the package's own `build` script. Delegating is what the guard is for:
 * a prepack that repeats a compiler line builds something that can drift from what `build` means, and a
 * prepack that runs nothing leaves the pack shipping the directory whatever command last wrote.
 */
function runsOwnBuild(prepack: string): boolean {
  return /(?:^|[\s;&|(])[\w./-]+\s+run\s+build(?=$|[\s;&|)])/u.test(prepack);
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

  it('declares a prepack that builds, so a pack ships a tree it compiled', () => {
    // `pnpm pack` packages whatever `dist` was last left as. Without a prepack the artifact a consumer
    // receives is a property of the last command anyone ran in this directory, which is the one failure a
    // published version cannot take back, so the guard is stated in the manifest rather than in the
    // workflow that happens to build first.
    const offenders: string[] = [];
    for (const manifest of publishable()) {
      const scripts = field(manifest, 'scripts');
      if (typeof scripts !== 'object' || scripts === null || Array.isArray(scripts)) {
        offenders.push(`${manifest.dir} carries no scripts object, so it declares no prepack to run`);
        continue;
      }
      const block = scripts as Record<string, unknown>;
      const prepack = block['prepack'];
      const build = block['build'];
      if (typeof prepack !== 'string' || prepack.trim().length === 0) {
        offenders.push(
          `${manifest.dir} declares no prepack, so a pack of it ships the dist some earlier command left ` +
            'behind, including a dist from before the source it publishes',
        );
        continue;
      }
      if (typeof build !== 'string' || build.trim().length === 0) {
        offenders.push(`${manifest.dir} declares prepack as ${prepack} and no build script for it to run`);
        continue;
      }
      if (!runsOwnBuild(prepack)) {
        offenders.push(
          `${manifest.dir} declares prepack as ${prepack}, which runs no build script, so the pack builds ` +
            `nothing and the package's own build is ${build}`,
        );
      }
    }
    expect(
      offenders,
      'a publish would upload a tarball whose bytes are whatever the tree last happened to hold:\n' +
        `${offenders.join('\n')}`,
    ).toEqual([]);
  });

  it('ships the directory every entry point lives in', () => {
    for (const manifest of manifests()) {
      const files = field(manifest, 'files');
      expect(Array.isArray(files) && files.length > 0, `${manifest.dir} declares no files list`).toBe(true);
      const shipped = (files as unknown[]).map((entry) => String(entry).replace(/^\.\//u, ''));
      for (const target of entryPoints(manifest.fields)) {
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

  it('reads the way in a manifest names with one bin target, which a one-command package writes short', () => {
    // `@ashaveri/cli` and the gateway each ship one command and name it as a map, the form npm uses when a
    // package ships several. A manifest with a single command may write the same fact as the string npm
    // accepts for it, and then a reader that walked only the map finds an entry point in no manifest: not a
    // refusal but an empty list, which the check above holds to a shipped directory of nothing.
    const single = entryPoints({ bin: './dist/cli.js' });
    expect(single, `a manifest naming its one command as a string read as ${single.join(', ') || 'nothing'}`).toEqual(
      ['./dist/cli.js'],
    );
    const mapped = entryPoints({ bin: { ashaveri: './dist/cli.js' } });
    expect(mapped, 'the one command named as a map read differently from the same command named as a string').toEqual(
      single,
    );
  });

  it('reads the way in a manifest names with the two fields a resolver reads before the exports map', () => {
    // Five of the six publishable manifests state their built output as `main` and `types` as well as writing
    // the same two paths into the `exports` map, so the shape is read every time this file resolves a package,
    // and both statements name the same bytes. That is also why the shape is weighed here on its own: a reader
    // that walked only the map returns those two paths for every manifest in this workspace and nothing at all
    // for one that states no map, and the list it returns is what the shipped-directory check above and the
    // built-entry-point check below go on. Dropping the two fields from the shared reader is therefore a
    // shorter list, not a wrong answer, and this is the case that stops it being silent.
    const stated = entryPoints({ main: './dist/index.js', types: './dist/index.d.ts' });
    expect(
      stated,
      `a manifest stating main and types with no exports map read as ${stated.join(', ') || 'nothing'}`,
    ).toEqual(['./dist/index.js', './dist/index.d.ts']);
  });

  it("states the root's Node floor in every publishable manifest, which a manager enforces only where the consumer opts in", () => {
    const wanted = rootEnginesRange();
    const declared = parseRange(wanted, `${ROOT_MANIFEST} engines.node`);
    const disagreed: string[] = [];
    for (const manifest of publishable()) {
      // Compared as a range and not as text, on the reader `pinned-node.test.ts` states the convention
      // with: `>= 26.13.0 <27` is the root's promise re-spaced, and `>=26.0.0` is a floor widened. A text
      // match reddens the first and passes the second, which is the opposite of what this field claims.
      const line = floorDisagreement(manifest.dir, nodeRangeOf(manifest), declared, wanted);
      if (line !== undefined) disagreed.push(line);
    }
    expect(
      disagreed,
      'a consumer reading these manifests finds no Node floor, or a floor other than the one this workspace ' +
        `declares for itself:\n${disagreed.join('\n')}`,
    ).toEqual([]);
  });

  it('reads one floor from a manifest however it spaces the operators of its range', () => {
    const wanted = rootEnginesRange();
    const declared = parseRange(wanted, `${ROOT_MANIFEST} engines.node`);
    const rootFloor = floorOf(declared, `${ROOT_MANIFEST} engines.node`);
    const misread: string[] = [];
    for (const manifest of publishable()) {
      const stated = nodeRangeOf(manifest);
      if (stated === undefined) {
        misread.push(`${manifest.dir} states no engines.node, so it states no spelling of a floor to read`);
        continue;
      }
      // Every manifest here is written without the space, so the spaced spelling of it is the one this
      // tolerance exists for, and both questions the field answers are asked of it: whether it is still the
      // workspace's promise, and what floor it states. A reader that split the range on a space it was told
      // to allow would report a re-typed manifest as a moved floor.
      const spaced = spacedOperators(stated);
      const read = parseRange(spaced, `${manifest.dir} engines.node`);
      if (!rangesAgree(read, declared)) {
        misread.push(`${manifest.dir} states ${spaced}, which this reader does not read as ${wanted}`);
      }
      const floor = floorOf(read, `${manifest.dir} engines.node`);
      if (compareVersions(floor, rootFloor) !== 0) {
        misread.push(`${manifest.dir} states ${spaced}, whose floor is ${floor.text} and not ${rootFloor.text}`);
      }
    }
    expect(
      misread,
      `a spacing is not a promise, and these manifests were held to a different one than they state:\n${misread.join('\n')}`,
    ).toEqual([]);
  });

  it('names the manifest whose Node range is wider than the one the workspace declares', () => {
    const wanted = rootEnginesRange();
    const declared = parseRange(wanted, `${ROOT_MANIFEST} engines.node`);
    const planted = [
      { stated: '>=26.0.0 <27', reads: 'a floor lowered below the release .nvmrc pins' },
      { stated: '>=26.13.0 <28', reads: 'a ceiling raised past the one the workspace sets for itself' },
      { stated: '>=26.13.0', reads: 'no ceiling at all, so every release from 27 up is admitted' },
      { stated: '>26.13.0 <27', reads: 'a floor that leaves the pinned release out' },
    ];
    const reported = planted.map((one) => ({
      ...one,
      line: floorDisagreement(PLANTED_DIR, one.stated, declared, wanted),
    }));
    const silent = reported.filter((one) => one.line === undefined).map((one) => `${one.stated}, ${one.reads}`);
    expect(
      silent,
      `the comparison agreed with a manifest admitting releases ${ROOT_MANIFEST} does not:\n${silent.join('\n')}`,
    ).toEqual([]);
    // Naming which manifest disagrees is the whole use of a refusal at this field: six manifests state one
    // range each, and a line that says only "disagreed" sends a reader to diff six files by hand.
    const unnamed = reported
      .filter((one) => {
        const line = one.line ?? '';
        return !line.includes(PLANTED_DIR) || !line.includes(one.stated) || !line.includes(wanted);
      })
      .map((one) => `${one.stated}: ${one.line ?? 'nothing reported'}`);
    expect(
      unnamed,
      `a reported disagreement names neither the manifest, its own range, and the range declared in ${ROOT_MANIFEST}:\n${unnamed.join('\n')}`,
    ).toEqual([]);
    // Two controls, because a check that reports every range it is handed passes this case too: the declared
    // range restated by a manifest is agreement, and a manifest stating no floor is reported rather than
    // agreed with.
    expect(
      floorDisagreement(PLANTED_DIR, wanted, declared, wanted),
      `a manifest stating ${wanted} was reported as disagreeing with the ${wanted} the workspace declares`,
    ).toBeUndefined();
    const bare = floorDisagreement(PLANTED_DIR, undefined, declared, wanted) ?? '';
    expect(bare.includes(PLANTED_DIR), `a manifest with no engines.node was reported without ${PLANTED_DIR}`).toBe(true);
    expect(bare.includes(wanted), `a manifest with no engines.node was reported without the floor it owes: ${bare}`).toBe(true);
  });

  it('refuses a Node range it cannot read instead of reading it as agreement', () => {
    const wanted = rootEnginesRange();
    const declared = parseRange(wanted, `${ROOT_MANIFEST} engines.node`);
    // Every spelling here is one npm accepts in a range field and this reader does not understand, and the
    // caret is the likeliest of them in a manifest: it means roughly the promise the workspace makes, and a
    // reader that could not parse it would have to say so rather than book it as a match or a mismatch.
    for (const unreadable of ['^26.13.0', '~26.13.0', '26.x', '>=26.13.0 || <28']) {
      expect(
        () => floorDisagreement(PLANTED_DIR, unreadable, declared, wanted),
        `${unreadable} was read as a range rather than refused, where ${ROOT_MANIFEST} declares ${wanted}`,
      ).toThrow(`${PLANTED_DIR} engines.node declares "${unreadable}"`);
    }
  });

  it('finds each built entry point where the manifest says it will be', () => {
    // A suite runs before a build as readily as after one, so a set with no output on disk anywhere is a
    // skip: what is asserted is that what the build emitted sits where the manifest promises it, which is
    // the same promise a consumer of the tarball takes. A set that is part built is not a skip. The
    // packages named by such a run would upload a tarball of nothing beside the built ones, so the
    // unbuilt directory is reported by package and name, and only then are the entry points read. Where
    // that directory is comes from the manifest's own entry points, so a package that ships its build from
    // somewhere else is weighed against where it says it is rather than against a name kept in this file.
    const publishSet = publishable();
    const unbuilt = publishSet.filter((manifest) => !outputDirs(manifest).some((dir) => existsRepoFile(`${manifest.dir}/${dir}`)));
    if (unbuilt.length === publishSet.length) return;
    expect(
      unbuilt.map((manifest) => `${manifest.name}: ${outputDirs(manifest).map((dir) => `${manifest.dir}/${dir}`).join(', ')}`),
      'the publish set is part built, so each package named here would upload a tarball with no output:',
    ).toEqual([]);
    const missing: string[] = [];
    for (const manifest of publishSet) {
      for (const target of entryPoints(manifest.fields)) {
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

  it('keeps a private package out of every field a consumer installs', () => {
    // The held-back set is read off the manifests rather than written here, so a fifth private package is
    // refused in every publishable manifest the moment it is flagged, with no edit to this file. That the
    // set is not empty is pinned by the case holding `private` as the only statement of publishability,
    // which answers for this one never having to refuse nothing.
    const held = manifests()
      .filter((manifest) => !isPublishable(manifest.fields))
      .map((manifest) => manifest.name);
    const publishing = publishable();
    const offenders: string[] = [];
    for (const manifest of publishing) {
      for (const key of CONSUMER_INSTALLED_FIELDS) {
        for (const name of dependencyNames(manifest, key)) {
          if (held.includes(name)) {
            offenders.push(`${manifest.dir} names ${name}, held back from a publish here, in ${key}, which npm installs`);
          }
        }
      }
      const allowed = PRIVATE_DEV_DEPENDENCIES[manifest.dir] ?? [];
      const declared = dependencyNames(manifest, 'devDependencies');
      for (const name of declared) {
        if (held.includes(name) && !allowed.includes(name)) {
          offenders.push(
            `${manifest.dir} names ${name}, held back from a publish here, in devDependencies, which no line of ` +
              'PRIVATE_DEV_DEPENDENCIES allows it to',
          );
        }
      }
      for (const name of allowed) {
        if (!held.includes(name)) {
          offenders.push(`${manifest.dir} is allowed to name ${name} in devDependencies, and ${name} carries no private flag`);
        } else if (!declared.includes(name)) {
          offenders.push(`${manifest.dir} is allowed to name ${name} in devDependencies and no longer does`);
        }
      }
    }
    for (const dir of Object.keys(PRIVATE_DEV_DEPENDENCIES)) {
      if (!publishing.some((manifest) => manifest.dir === dir)) {
        offenders.push(`${dir} is on PRIVATE_DEV_DEPENDENCIES and publishes nothing, so the allowance waits for a manifest that is not here`);
      }
    }
    expect(
      offenders,
      `the packages held back from a publish are ${held.join(', ')}; a publishable manifest naming one where an ` +
        `installer looks leaves a consumer resolving a package no registry serves:\n${offenders.join('\n')}`,
    ).toEqual([]);
  });

  it('holds the document to the same private devDependency list this file keeps', () => {
    const paragraph = specDevDependencyParagraph();
    const held = manifests()
      .filter((manifest) => !isPublishable(manifest.fields))
      .map((manifest) => manifest.name);
    const publishing = publishable();
    const offenders: string[] = [];

    // The names the allowance covers, spelled the way the document spells them: as the package that carries
    // the dependency rather than as the directory holding its manifest.
    const allowed: string[] = [];
    for (const [dir, names] of Object.entries(PRIVATE_DEV_DEPENDENCIES)) {
      const manifest = publishing.find((one) => one.dir === dir);
      if (manifest === undefined) {
        offenders.push(`${dir} is on PRIVATE_DEV_DEPENDENCIES and matches no publishable manifest, so no name in the document answers for it`);
        continue;
      }
      if (names.some((name) => held.includes(name))) allowed.push(manifest.name);
    }

    // The names the enumeration states, and only there. The private names are dropped rather than matched,
    // because the clause names the signer it is about.
    const scoped = new RegExp(`${SCOPE}[a-z0-9-]+`, 'gu');
    const stated = [
      ...new Set([...specListingClause(paragraph).matchAll(scoped)].map((found) => String(found[0]))),
    ]
      .filter((name) => !held.includes(name))
      .sort();

    for (const name of allowed) {
      if (!stated.includes(name)) {
        offenders.push(`${name} is allowed a private package in devDependencies here, and ${RECEIPT_SPEC} does not name it`);
      }
    }
    for (const name of stated) {
      if (!allowed.includes(name)) {
        offenders.push(`${RECEIPT_SPEC} names ${name} as carrying a private devDependency, and PRIVATE_DEV_DEPENDENCIES allows no such line`);
      }
    }

    // The one count the paragraph states, held to the one list it enumerates, so a list that grows in one
    // place cannot leave a number standing in the other.
    const counts = new RegExp(`^([A-Za-z]+) of the ([A-Za-z]+) ${SPEC_POSITION_ANCHOR}`, 'u').exec(paragraph);
    const namingCount = counts?.[1];
    const publishCount = counts?.[2];
    if (namingCount === undefined || publishCount === undefined) {
      throw new Error(`${RECEIPT_SPEC} no longer opens that paragraph with the two counts this case reads`);
    }
    if (spelledNumber(namingCount) !== allowed.length) {
      offenders.push(`${RECEIPT_SPEC} opens by saying ${namingCount} of the packages publish a private name, and PRIVATE_DEV_DEPENDENCIES covers ${String(allowed.length)}`);
    }
    if (spelledNumber(publishCount) !== publishing.length) {
      offenders.push(`${RECEIPT_SPEC} says ${publishCount} packages publish at all, and ${String(publishing.length)} carry no private flag`);
    }

    expect(
      offenders,
      `the allowance covers ${[...allowed].sort().join(', ')} and the paragraph states ${stated.join(', ')}; ` +
        'one of the two moved alone:\n' +
        offenders.join('\n'),
    ).toEqual([]);
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

/**
 * The README names packages in three places besides its count: the Status sentence that lists them, the
 * publish-day badge block a comment holds back until there is something to badge, and the table under
 * "Packages".
 *
 * A count can be right beside the wrong names. The boundary review's finding C3 recorded three documents
 * stating three different numbers while each sentence was locally true, and the fix that closed it was a
 * ruling about which set is the promise, not a number typed into each place. So these cases ask membership,
 * walked off the workspace rather than compared against a list kept in this file, and they draw the
 * publishable line with `isPublishable`, the same rule the manifest and tarball readers use, because a
 * second copy of a boundary is a second boundary.
 */
describe('the packages the public README names, by name', () => {
  const publishableNames = (): string[] => publishable().map((manifest) => manifest.name);
  const privateNames = (): string[] =>
    manifests().filter((manifest) => !isPublishable(manifest.fields)).map((manifest) => manifest.name);

  /** The package names a slice of the README spells, in the order the document puts them. */
  function namedIn(text: string): string[] {
    return [...text.matchAll(/@ashaveri\/[a-z][a-z0-9-]*/giu)].map((found) => found[0] ?? '');
  }

  it('lists every publishable package in the Status sentence, and says why any private one appears there', () => {
    const status = sectionBody(readRepoFile(README), '## Status');
    const named = namedIn(status);
    const listed = [...new Set(named.filter((name) => publishableNames().includes(name)))].sort();
    expect(
      listed,
      `${README}'s Status sentence names ${listed.length} of the packages this workspace publishes: it should hold ` +
        `[${publishableNames().join(', ')}] and holds [${listed.join(', ')}]`,
    ).toEqual([...publishableNames()].sort());

    for (const name of privateNames()) {
      if (!named.includes(name)) continue;
      const clause = status
        .split(/(?<=[.!])\s+/u)
        .find((one) => one.includes(name));
      expect(
        clause ?? '',
        `the Status sentence names ${name}, which no registry holds, in a clause that does not say it waits: ` +
          JSON.stringify(clause ?? ''),
      ).toMatch(/"private": true|private flag|until|waits/iu);
    }
  });

  it('badges one name per publishable package on publish day, and none for a package that is still private', () => {
    const blocks = [...readRepoFile(README).matchAll(/<!--([\s\S]*?)-->/gu)].map((found) => found[1] ?? '');
    const badgeBlock = blocks.find((one) => one.includes('npmjs.com/package/'));
    if (badgeBlock === undefined) {
      throw new Error(`${README} carries no commented publish-day badge block, so the release has no badge list to check`);
    }
    const badged = [...new Set([...badgeBlock.matchAll(/npmjs\.com\/package\/(@ashaveri\/[a-z][a-z0-9-]*)/gu)]
      .map((found) => found[1] ?? ''))].sort();
    expect(
      badged,
      `the badge list would publish ${badged.length} shields against ${publishableNames().length} publishable ` +
        `packages: [${badged.join(', ')}]`,
    ).toEqual([...publishableNames()].sort());

    for (const name of privateNames()) {
      expect(
        badged.includes(name),
        `the badge list carries a badge for ${name}, whose manifest still says "private": true, so the release ` +
          'would advertise a package no registry holds',
      ).toBe(false);
    }
    for (const name of privateNames()) {
      expect(
        namedIn(badgeBlock).includes(name),
        `the badge block does not name ${name} at all, so the change that drops its private flag has no note here ` +
          'telling it to add a badge, and the count in the Status sentence will move alone',
      ).toBe(true);
    }
  });

  it('gives every workspace manifest one row in the package table and no row to a package the workspace does not hold', () => {
    const rows = tableRows(readRepoFile(README), '| Package | Purpose |');
    const tabled = rows.map((row, at) => {
      const cell = row[1] ?? '';
      const [name] = namedIn(cell);
      if (name === undefined) {
        throw new Error(`row ${String(at + 1)} of the package table names no package: ${JSON.stringify(cell)}`);
      }
      return name;
    });
    expect(
      [...new Set(tabled)].sort(),
      `the package table holds [${[...new Set(tabled)].join(', ')}] against the workspace's ` +
        `[${manifests().map((manifest) => manifest.name).join(', ')}]`,
    ).toEqual(manifests().map((manifest) => manifest.name).sort());
    expect(tabled.length, `the package table lists ${manifests().length} packages across ${String(tabled.length)} rows`).toBe(
      new Set(tabled).size,
    );
  });
});
