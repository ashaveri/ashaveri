import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { newPopCredential, serializeCredentialFile } from '../src/access.js';
import { ACCESS_PART_NAME, parseAccessLine } from '../src/aclog.js';
import { bootBudget, bootServing, complete, signedGet } from './support/served-gateway.js';

/**
 * What the process owes the volume before it owes a caller an answer.
 *
 * One completion is served over HTTP, its body is read whole by the caller, and the gateway is stopped with
 * `SIGKILL` in the same turn. The volume holds the only witness, because a terminated process takes with it
 * every write it had asked for and had not finished waiting on. So the lines below are present only where
 * each request's line was handed to the log and awaited before its answer went out; where the write is fired
 * off beside the answer, one of them is missing and no reading afterwards can say which request lost it.
 *
 * The read beside each completion is the shape the loss arrived in: a receipt fetched over HTTP, answered in
 * full, its own line still in flight when the process stopped. It is repeated rather than run once because a
 * race lost on the first try proves as little as a race won on it.
 */

const BOOTS = 3;
/** The completion and the read of the receipt it filed. */
const LINES_PER_BOOT = 2;

const pop = newPopCredential({ id: 'flush-witness', scopes: ['read', 'complete'] });

let root = '';
let accessDir = '';
let volumeDir = '';
let credentialsPath = '';

async function logLines(): Promise<string[]> {
  const names = (await readdir(accessDir)).filter((each) => ACCESS_PART_NAME.test(each)).sort();
  const all: string[] = [];
  for (const name of names) {
    for (const line of (await readFile(join(accessDir, name), 'utf8')).split('\n')) {
      if (line.trim().length > 0) all.push(line);
    }
  }
  return all;
}

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'ashaveri-flush-witness-'));
  accessDir = join(root, 'access');
  volumeDir = join(root, 'volume');
  credentialsPath = join(root, 'credentials.json');
  await writeFile(credentialsPath, serializeCredentialFile({ version: 1, credentials: [pop.record] }), 'utf8');
  await Promise.all([mkdir(accessDir), mkdir(volumeDir)]);
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('an answered request whose line outlives the process', () => {
  it(
    'leaves one access line on the volume for each answer a killed process handed out',
    { timeout: bootBudget(BOOTS) + 20_000 },
    async () => {
      for (let round = 0; round < BOOTS; round += 1) {
        const served = await bootServing([
          '--receipts-dir', volumeDir,
          '--credentials-path', credentialsPath,
          '--access-log-path', accessDir,
        ]);
        const answered = await complete(served, pop);
        expect(answered.status, answered.text).toBe(200);
        const read = await signedGet(served, pop, `/v1/receipts/${String(answered.receiptId)}`);
        expect(read.status, read.body).toBe(200);
        await served.kill();
        const lines = await logLines();
        expect(
          lines.length,
          `round ${String(round)}: the caller held both answers, so the volume owes ${String((round + 1) * LINES_PER_BOOT)} lines and holds ${String(lines.length)}`,
        ).toBe((round + 1) * LINES_PER_BOOT);
      }
      const paths = (await logLines()).map((line) => parseAccessLine(line).p);
      expect(paths.filter((each) => each === '/v1/chat/completions')).toHaveLength(BOOTS);
      expect(paths.filter((each) => each.startsWith('/v1/receipts/'))).toHaveLength(BOOTS);
    },
  );

  it('records the answer it gave rather than a status the route never set', async () => {
    const served = await bootServing([
      '--receipts-dir', volumeDir,
      '--credentials-path', credentialsPath,
      '--access-log-path', accessDir,
    ]);
    const refused = await signedGet(served, pop, '/v1/receipts/rcpt_never_filed');
    expect(refused.status).toBe(404);
    await served.kill();
    const lines = (await logLines()).map((line) => parseAccessLine(line));
    const mine = lines.filter((each) => each.p === '/v1/receipts/rcpt_never_filed');
    expect(mine.map((each) => each.st)).toEqual([404]);
  }, bootBudget(1) + 20_000);
});
