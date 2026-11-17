import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, extname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The vectors job runs this package's `generate*` keys, one step each, and `tsconfig.scripts.json` is
 * the config that reads the files those keys name. Nothing connected the two: a key aimed at a path
 * outside `scripts/`, or at a script written as `.mjs`, would run there exactly as the others run and
 * be typechecked by no config, which is the state the third config exists to end.
 *
 * The same job's steps are read here for the same reason. The job states its own rule as one step per key,
 * because the diff gate that closes it can only refuse bytes a step above it wrote, so a family whose
 * generator the job never runs is a committed file carrying no pin at all. That gap is invisible to every
 * suite in this package and was found once by a hand comparing two files; these two rows make it a failure
 * instead.
 *
 * All the keys are read, not only the ones a step exists for, because a key with no step is still a
 * command someone can run and the typecheck answer does not change with the runner. The directory
 * comes out of that config rather than being repeated here: repeating it is how this file would start
 * passing on its own copy of an answer the config moved.
 */

const PKG = fileURLToPath(new URL('../', import.meta.url));
const SCRIPTS_CONFIG = join(PKG, 'tsconfig.scripts.json');
const WORKFLOW = join(PKG, '..', '..', '.github', 'workflows', 'ci.yml');

interface GenerateScript {
  readonly key: string;
  readonly command: string;
}

/** The manifest's own `generate*` entries. */
function generateScripts(): GenerateScript[] {
  const manifest = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8')) as {
    scripts?: Record<string, string>;
  };
  return Object.entries(manifest.scripts ?? {})
    .filter(([key]) => key.startsWith('generate'))
    .map(([key, command]) => ({ key, command }));
}

/**
 * The directories a tsconfig `include` array names, resolved against the file holding it. The config
 * carries comments, so the array is read out of the text instead of parsed as JSON, and a glob tail is
 * dropped: `scripts` and `scripts/**` ask for the same directory.
 */
function includedDirs(configPath: string): string[] {
  const listed = /"include"\s*:\s*\[([^\]]*)\]/u.exec(readFileSync(configPath, 'utf8'))?.[1];
  if (listed === undefined) {
    throw new Error(`${basename(configPath)} states no include array, so there is nothing to read here`);
  }
  const dirs = [...listed.matchAll(/"([^"]*)"/gu)]
    .map((found) => (found[1] ?? '').split('*')[0]?.replace(/[\\/]+$/u, '') ?? '')
    .filter((each) => each.length > 0)
    .map((each) => resolve(dirname(configPath), each))
    .filter((each) => existsSync(each));
  if (dirs.length === 0) {
    throw new Error(`${basename(configPath)} includes no directory that exists`);
  }
  return dirs;
}

/**
 * What a run command leaves once `node` and every token beginning with a dash are taken out: the file
 * it is told to load. A command leaving nothing, or leaving two things, is the case below reporting it.
 */
function operands(command: string): string[] {
  return command
    .trim()
    .split(/\s+/u)
    .filter((token) => token.length > 0 && !token.startsWith('-') && token !== 'node')
    .map((token) => token.replace(/^["']|["']$/gu, ''));
}

/**
 * Whether `target` lies under `dir`. Both sides are absolute by the time they reach here, so a `..`
 * written into a command moves the file out of the directory rather than looking like it stayed.
 */
function inside(dir: string, target: string): boolean {
  const rel = relative(dir, target);
  return rel.length > 0 && !rel.startsWith('..') && !isAbsolute(rel);
}

const scripts = generateScripts();
const dirs = includedDirs(SCRIPTS_CONFIG);

/**
 * The keys the vectors job runs this package for, read off its own steps.
 *
 * A step is taken by the package it names, so `packages/attest-core`'s generator is no step of this one and
 * never joins the set: the rule below is about the pin on the files this package commits. The file is read as
 * text because a YAML dependency would be a second answer to what a step is, and the workflow's own comment
 * above the steps is the sentence this row holds it to.
 */
function generateKeysTheJobRuns(): string[] {
  expect(existsSync(WORKFLOW), `${relative(PKG, WORKFLOW)} is not there to be read`).toBe(true);
  return [
    ...readFileSync(WORKFLOW, 'utf8').matchAll(/pnpm (?:-C|--dir) packages\/fixtures\s+(generate[\w:.-]*)/gu),
  ].map((found) => found[1] ?? '');
}

describe('the scripts a generate key runs', () => {
  it('are read from a manifest with something in it', () => {
    expect(scripts.length, 'the manifest carries no generate* key to check').toBeGreaterThan(0);
  });

  it('name one file each', () => {
    for (const { key, command } of scripts) {
      expect(operands(command), `${key} runs ${command}, which leaves no single file operand`).toHaveLength(1);
    }
  });

  it('are typechecked by the config that includes them', () => {
    for (const { key, command } of scripts) {
      const [operand] = operands(command);
      if (operand === undefined) continue;
      const target = resolve(PKG, operand);
      expect(extname(target), `${key} runs ${operand}, which is not a .ts file`).toBe('.ts');
      expect(
        dirs.some((dir) => inside(dir, target)),
        `${key} runs ${operand}, outside the directories ${basename(SCRIPTS_CONFIG)} includes`,
      ).toBe(true);
      expect(existsSync(target) && statSync(target).isFile(), `${key} runs ${operand}, which is not there`).toBe(
        true,
      );
    }
  });

  it('are each run by a step of the vectors job, which runs none this manifest does not define', () => {
    // Both directions of one set. A key the job never runs leaves its committed file unpinned: the gate
    // below that diff fails only for bytes a step above it wrote. A step naming no key leaves a job that
    // stops for a command nobody can find in the manifest. The count beside the set is the job's own
    // "one step per generate key", which a repeated step would quietly break.
    const steps = generateKeysTheJobRuns();
    expect(
      [...new Set(steps)].sort(),
      'the generate keys the vectors job runs, against the keys packages/fixtures/package.json defines',
    ).toEqual(scripts.map((one) => one.key).sort());
    expect(steps.length, `one step per key, and the job carries ${steps.join(', ')}`).toBe(
      new Set(steps).size,
    );
  });
});
