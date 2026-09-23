/**
 * The single-file build: one artifact that runs where nothing is installed.
 *
 * `build` compiles TypeScript into `dist` the way npm expects, and that package still needs its
 * dependencies next to it. This is the other artifact, for the case the package cannot serve: an
 * auditor with a receipt, a policy and a deployment manifest on a machine with no network, no
 * checkout and no `node_modules`. Everything this command reads is inside the file, so the only
 * things outside it are the four inputs and Node itself.
 *
 * What is deliberately not here: no vendored binary, because the artifact is the same TypeScript the
 * package publishes and a bundled native module would be both a second license question and a second
 * thing to trust. No source map, because a map is a companion file, and a "single file" that needs one
 * is not single. The license banner and the third-party notices a bundler keeps inline are what make
 * the copy-away honest about what is inside.
 */
import { readFileSync } from 'node:fs';
import { stdout } from 'node:process';
import { build } from 'esbuild';

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const version = typeof manifest.version === 'string' ? manifest.version : 'unknown';
const out = 'dist/ashaveri-bundle.mjs';

await build({
  entryPoints: ['src/cli.ts'],
  outfile: out,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  // The version of a file that is copied to a machine with nothing beside it cannot come from a
  // manifest read at runtime, so the one this was built under is stamped in at build time.
  define: { BUNDLE_VERSION: JSON.stringify(version) },
  banner: {
    // A banner is spliced in ahead of the code, so it has to be a comment: prose without the markers
    // is the first statement of the file, and the file then refuses to parse on the machine that was
    // supposed to be able to run it.
    js:
      '/* ashaveri CLI ' +
      version +
      ', bundled from source for offline use. Apache-2.0; the license and notice texts are the ones ' +
      'in the package this was built from. Third-party notices are kept inline below, and nothing in ' +
      'this file is a vendored binary. */',
  },
  legalComments: 'inline',
  sourcemap: false,
  logLevel: 'warning',
});

stdout.write(`bundled ${out} from @ashaveri/cli ${version}\n`);
