import { readdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { checkId } from '../records.js';
import { UsageError } from '../usage.js';

const ACCESS_FILE = /^access-(\d{4}-\d{2}-\d{2})-(\d{3})\.jsonl$/u;

export interface ScrubMarker {
  t: number;
  credential: string;
  removed: number;
  files: number;
}

export interface ScrubResult {
  removed: number;
  files: number;
  marker: string | null;
}

export interface AccessLogFlags {
  'access-log'?: string;
  credential?: string;
  json?: boolean;
}

/**
 * Erasure with a receipt of itself. An erasure request that leaves a silence cannot be told apart
 * from a gap in the retention, so the scrub records that it happened, names the credential it
 * emptied, and carries a count and nothing else.
 *
 * A line this program cannot read stays in the file exactly as it was found, byte for byte: the
 * erasure was asked for one credential's records, and a scrub that quietly discarded what it did not
 * understand is not a scrub. The bytes that can move are the ones the writer always appends, so the
 * promise is per-line preservation plus a possible trailing newline in a file that had none.
 */
export async function accesslogScrub(dir: string, credential: string, now: () => number): Promise<ScrubResult> {
  const names = await readdirOrThrow(dir);
  const targets = names.filter((each) => ACCESS_FILE.test(each)).sort();
  if (targets.length === 0) {
    throw new UsageError('--access-log holds no access-*.jsonl files; point it at the directory signerd writes');
  }
  let removed = 0;
  let touched = 0;
  for (const name of targets) {
    const path = join(dir, name);
    const lines = (await readFile(path, 'utf8')).split('\n');
    const kept: string[] = [];
    let present = 0;
    for (const line of lines) {
      if (line.length === 0) continue;
      present += 1;
      let cred: unknown;
      try {
        cred = (JSON.parse(line) as { cred?: unknown }).cred;
      } catch {
        kept.push(line);
        continue;
      }
      if (cred === credential) {
        removed += 1;
        continue;
      }
      kept.push(line);
    }
    if (kept.length === present) continue;
    if (kept.length === 0) {
      // A fully scrubbed part is unlinked, not renamed. A copy under a name the gateway's retention
      // can no longer match would keep every removed line on the volume forever, and it would read
      // as a completed erasure that left the data behind.
      await unlink(path);
    } else {
      await writeAtomic(path, `${kept.join('\n')}\n`);
    }
    touched += 1;
  }
  if (removed === 0) return { removed: 0, files: 0, marker: null };
  const marker = await nextScrubName(dir, now());
  const receipt: ScrubMarker = { t: now(), credential, removed, files: touched };
  await writeAtomic(join(dir, marker), `${JSON.stringify(receipt)}\n`);
  return { removed, files: touched, marker };
}

async function readdirOrThrow(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read --access-log directory '${dir}': ${reason}`);
  }
}

/**
 * The marker is named like a log part, one family of its own, so the retention sweep ages it out on
 * the day in its name and the log never reads one as a record.
 */
async function nextScrubName(dir: string, atMillis: number): Promise<string> {
  const day = new Date(atMillis).toISOString().slice(0, 10);
  const names = await readdirOrThrow(dir);
  let seq = 0;
  for (;;) {
    const candidate = `scrub-${day}-${String(seq).padStart(3, '0')}.jsonl`;
    if (!names.includes(candidate)) return candidate;
    seq += 1;
  }
}

/**
 * Same-directory write and rename, because this rewrites files a running gateway is appending to: a
 * reader that polls the mtime never has to see half of a scrub.
 */
async function writeAtomic(path: string, text: string): Promise<void> {
  const tmp = `${path}.tmp-${String(process.pid)}`;
  await writeFile(tmp, text, { mode: 0o600 });
  await rename(tmp, path);
}

export async function runAccessLog(sub: string[], flags: AccessLogFlags, now: () => number): Promise<number> {
  const name = sub[0];
  if (name !== 'scrub') {
    throw new UsageError('expected an accesslog command: scrub');
  }
  const dir = flags['access-log'];
  if (dir === undefined) throw new UsageError('accesslog scrub needs --access-log <dir>');
  const credential = flags.credential;
  if (credential === undefined) throw new UsageError('accesslog scrub needs --credential <id>');
  // Checked before any file is rewritten: this value comes back in the summary line and in the
  // marker, and an erasure whose own report can carry a forged line is a receipt that proves nothing.
  checkId(credential, '--credential');
  const result = await accesslogScrub(dir, credential, now);
  if (flags.json === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  }
  const noun = result.files === 1 ? 'file' : 'files';
  const count = result.removed === 1 ? 'record' : 'records';
  process.stdout.write(`removed ${String(result.removed)} ${count} for ${credential} in ${String(result.files)} ${noun}\n`);
  if (result.marker !== null) {
    process.stdout.write(`marker: ${result.marker}\n`);
  }
  return 0;
}
