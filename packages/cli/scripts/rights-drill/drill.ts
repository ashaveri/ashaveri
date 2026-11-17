import { createInterface } from 'node:readline';
import { mkdirSync, rmSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  hostLine,
  legCoordinated,
  legHoldConflict,
  legNotification,
  legQuiesced,
  legRestore,
  legSubjectAccess,
  shipped,
  type ChildResult,
  type LegOutcome,
  type Run,
  type Verdict,
} from './legs.ts';

/**
 * Which legs of a rights exercise this estate can run today, against bytes nobody is.
 *
 * The plan's managed-custody offer is gated on privacy and operations approving the service and its
 * exceptions. That approval reads evidence, and the evidence is this: a leg that ships is run and its
 * observed numbers recorded, and a leg that does not ship is named as missing beside the exact refusal
 * the shipped code gives when it is asked for. Nothing here reports a leg as working because a document
 * says it should, and nothing here states that any duty is discharged: the rows say what a program did
 * to bytes in a temporary directory.
 *
 * Run it as `pnpm drill:rights` from the workspace root, which builds first: the legs drive the built
 * command, the built gateway and the built store, because a drill that exercised a re-typed copy of them
 * would be a claim about the copy.
 *
 * The screen gets a table and the failing lines. The full record, every check with its expectation and
 * its observation, every command with its exit status, and every note, goes to the file whose path the
 * run prints last. Nothing is written inside the repository, and no identity is a person's.
 */

/** What this run expects to be true of each leg, so a verdict that moved is a failure it reports. */
const LEGS: readonly { leg: number; built: boolean }[] = [
  { leg: 1, built: false },
  { leg: 2, built: true },
  { leg: 3, built: false },
  { leg: 4, built: true },
  { leg: 5, built: true },
  { leg: 6, built: false },
];

interface Options {
  record: string | null;
  keep: boolean;
  step: boolean;
  help: boolean;
  only: number[] | null;
}

const USAGE = `usage: node scripts/rights-drill/drill.ts [options]

  --record <file>   Where to write the full record. Default: a file in the system temporary directory.
  --keep            Leave the run's temporary store on the volume and print its path.
  --only <legs>     Comma-separated leg numbers to run, in order. Default: all six.
  --step            Wait for a keypress between legs. Only on a terminal: a piped or CI run never waits.
  --help            Print this and exit 0.
`;

function parseArgs(argv: readonly string[]): Options {
  const options: Options = { record: null, keep: false, step: false, help: false, only: null };
  for (let at = 0; at < argv.length; at += 1) {
    const flag = argv[at];
    if (flag === '--help' || flag === '-h') options.help = true;
    else if (flag === '--keep') options.keep = true;
    else if (flag === '--step') options.step = true;
    else if (flag === '--record') {
      const value = argv[at + 1];
      if (value === undefined || value.startsWith('--')) throw new Error('drill: --record wants a file path');
      options.record = resolve(value);
      at += 1;
    } else if (flag === '--only') {
      const value = argv[at + 1];
      const legs = (value ?? '').split(',').map((one) => Number(one.trim()));
      if (legs.length === 0 || legs.some((one) => !Number.isInteger(one) || one < 1 || one > ORDER.length)) {
        throw new Error(`drill: --only wants leg numbers from 1 to ${String(ORDER.length)}`);
      }
      options.only = legs;
      at += 1;
    } else {
      throw new Error(`drill: unexpected argument '${String(flag)}'`);
    }
  }
  return options;
}

const say = (text: string): void => {
  process.stdout.write(`${text}\n`);
};

/**
 * The pause an operator asked for, and only where an operator is present.
 *
 * Three conditions, because a drill that blocks on a keypress in a CI job is a hung job: the flag, a
 * terminal on both ends, and no continuous-integration environment. A piped run gets a line saying the
 * pause was skipped rather than a silence.
 */
async function pauseIfAsked(step: boolean, between: string): Promise<void> {
  if (!step) return;
  const interactive = process.stdin.isTTY === true && process.stdout.isTTY === true && process.env['CI'] === undefined;
  if (!interactive) {
    say(`  (pause before ${between} skipped: no terminal, or CI is set)`);
    return;
  }
  await new Promise<void>((done) => {
    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    prompt.question(`  press enter to run ${between} `, () => {
      prompt.close();
      done();
    });
  });
}

function verdictOf(leg: LegOutcome, expected: boolean): Verdict {
  const passed = leg.checks.every((one) => one.passed);
  if (!passed) return 'NOT EXERCISED';
  return expected ? 'EXERCISED' : 'NOT BUILT';
}

function column(value: string, width: number): string {
  return value.length >= width ? value : `${value}${' '.repeat(width - value.length)}`;
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : `${' '.repeat(width - value.length)}${value}`;
}

/** The table the screen shows: one row per leg, and the failed lines under it. */
function printTable(legs: readonly LegOutcome[]): void {
  say(`${column('leg', 3)}  ${column('mechanism', 26)}  ${column('verdict', 13)}  ${column('checks', 7)}  what was seen`);
  for (const leg of legs) {
    const failed = leg.checks.filter((one) => !one.passed).length;
    const count = `${String(leg.checks.length - failed)}/${String(leg.checks.length)}`;
    say(`${pad(String(leg.leg), 3)}  ${column(leg.name, 26)}  ${column(leg.verdict, 13)}  ${column(count, 7)}  ${leg.summary}`);
    for (const one of leg.checks) {
      if (one.passed) continue;
      say(`     FAILED  ${one.name}`);
      say(`             expected ${one.expect}`);
      say(`             observed ${one.observed}`);
    }
    for (const missing of leg.missing) {
      say(`     missing ${missing}`);
    }
  }
}

/**
 * The legs in the order they run, each labelled with what the pause before it is called.
 *
 * One leg at a time is selectable, because a leg that has to be read on a screen next to a failing check
 * is a leg somebody has to be able to run alone, and the whole drill otherwise boots a gateway.
 */
const ORDER: readonly { leg: number; pauseBefore: string; run: (run: Run) => Promise<LegOutcome> }[] = [
  { leg: 1, pauseBefore: '', run: legSubjectAccess },
  { leg: 2, pauseBefore: 'the quiesced erasure', run: legQuiesced },
  { leg: 3, pauseBefore: 'the coordinated erasure', run: legCoordinated },
  { leg: 4, pauseBefore: 'the hold conflict', run: legHoldConflict },
  { leg: 5, pauseBefore: 'the restore', run: legRestore },
  { leg: 6, pauseBefore: 'the notification check', run: legNotification },
];

async function main(argv: readonly string[]): Promise<number> {
  const options = parseArgs(argv);
  if (options.help) {
    say(USAGE);
    return 0;
  }
  const here = fileURLToPath(new URL('.', import.meta.url));
  const cli = resolve(here, '../../dist/cli.js');
  const root = await mkdtemp(join(tmpdir(), 'ashaveri-rights-drill-'));
  const startedAt = new Date();
  const run: Run = {
    dir(name: string): string {
      const dir = join(root, name);
      mkdirSync(dir, { recursive: true });
      return dir;
    },
    shipped(args: readonly string[]): Promise<ChildResult> {
      return shipped(cli, args);
    },
  };

  say(`rights exercise drill, synthetic identities only, started ${startedAt.toISOString()}`);
  say(`${hostLine()}`);
  say(`temporary store: ${root}`);

  const legs: LegOutcome[] = [];
  for (const entry of ORDER) {
    if (options.only !== null && !options.only.includes(entry.leg)) continue;
    if (entry.pauseBefore.length > 0) await pauseIfAsked(options.step, entry.pauseBefore);
    legs.push(await entry.run(run));
  }

  const settled = legs.map((leg) => ({ ...leg, verdict: verdictOf(leg, (LEGS.find((one) => one.leg === leg.leg) ?? { built: leg.built }).built) }));
  printTable(settled);

  const finishedAt = new Date();
  // The record outlives the store it describes, so the default path cannot sit inside the directory the
  // run clears: an operator who ran the command without flags would have printed a path to a file the
  // same command had just deleted.
  const recordPath = options.record ?? join(tmpdir(), 'ashaveri-rights-drill-records', `rights-drill-${startedAt.toISOString().replace(/[:.]/gu, '-')}.json`);
  const counts = {
    legs: settled.length,
    exercised: settled.filter((one) => one.verdict === 'EXERCISED').length,
    not_built: settled.filter((one) => one.verdict === 'NOT BUILT').length,
    failed: settled.filter((one) => one.verdict === 'NOT EXERCISED').length,
    checks: settled.reduce((sum, one) => sum + one.checks.length, 0),
    checks_failed: settled.reduce((sum, one) => sum + one.checks.filter((each) => !each.passed).length, 0),
  };
  const missing = settled.flatMap((one) => one.missing);
  await mkdir(join(recordPath, '..'), { recursive: true });
  await writeFile(
    recordPath,
    `${JSON.stringify({
      started: startedAt.toISOString(),
      finished: finishedAt.toISOString(),
      duration_ms: Math.round(finishedAt.getTime() - startedAt.getTime()),
      host: hostLine(),
      argv: [...argv],
      store: options.keep ? root : `${root} (removed at the end of the run)`,
      counts,
      legs: settled,
      missing,
    }, null, 2)}\n`,
    'utf8',
  );
  if (!options.keep) {
    try {
      rmSync(root, { recursive: true, force: true });
    } catch (error) {
      say(`store left on the volume: the run could not remove ${root}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  say(counts.failed === 0 ? `verdict: every leg reported what the code did (${String(counts.exercised)} exercised, ${String(counts.not_built)} not built)` : `verdict: ${String(counts.failed)} leg(s) did not report as pinned`);
  say(`record: ${recordPath}`);
  return counts.failed === 0 ? 0 : 1;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    say(`drill: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
    process.exitCode = 1;
  },
);
