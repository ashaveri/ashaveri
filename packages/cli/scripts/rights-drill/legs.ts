import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { cpus, release } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CREDENTIALS_FILE_VERSION,
  HOST_CLOCK_SOURCE,
  RECEIPT_STORE_FILE,
  CredentialStore,
  buildGateway,
  openFileAccessLog,
  openFileReceiptStore,
  readReceiptStoreCheckpoint,
  type AccessLog,
  type GatewayInstance,
  type ReceiptStore,
} from '@ashaveri/signerd';
import { HOLD_RECORD_LIMITS, INCIDENT_BUNDLE_LIMITS } from '@ashaveri/receipt';
import { generatePart, partName, subjectCredential } from '../erasure-pass/part-fixture.ts';
import { EMPTY_SHA256 } from '../erasure-pass/unit-facts.ts';
import {
  digestOf,
  holdOver,
  holdOverEverything,
  holdOverOther,
  readVolume,
  renderLine,
  syntheticSubject,
  volumeBytes,
  type Subject,
  type VolumeFacts,
} from './synth.ts';

/**
 * The six legs, each of which either runs shipped behaviour and reports what it saw, or reports that
 * nothing shipped answers the call.
 *
 * Every leg states its arithmetic as checks carrying an expectation and an observation, so a reader of
 * the record can see the number behind a verdict without rerunning anything. A leg whose checks all pass
 * is `EXERCISED` when it says the mechanism ships and `NOT BUILT` when it says the mechanism is missing;
 * a leg whose checks do not all pass is `NOT EXERCISED`, and an unbuilt leg that stops refusing is a
 * failed leg rather than a passing one, which is what keeps a `NOT BUILT` row from becoming a claim.
 *
 * Nothing here writes inside the repository, and no identity here is a person's.
 */

export type Verdict = 'EXERCISED' | 'NOT BUILT' | 'NOT EXERCISED';

export interface Check {
  name: string;
  expect: string;
  observed: string;
  passed: boolean;
}

export interface LegOutcome {
  leg: number;
  name: string;
  /** What the row's verdict means, in one clause printed beside it. */
  summary: string;
  built: boolean;
  verdict: Verdict;
  checks: Check[];
  commands: string[];
  notes: string[];
  /** The mechanisms a `NOT BUILT` row names as missing. */
  missing: string[];
  readings?: { before: VolumeFacts; after: VolumeFacts };
}

export interface ChildResult {
  status: number;
  stdout: string;
  stderr: string;
  command: string;
}

export interface Run {
  /** A directory of this run's own, under the run root, created on demand. */
  dir(name: string): string;
  /** The built command-line program, as a child process with its real exit status. */
  shipped(args: readonly string[]): Promise<ChildResult>;
}

function check(name: string, expect: string, observed: string, passed: boolean): Check {
  return { name, expect, observed, passed };
}

/** A check whose expectation is a literal; `passed` is derived unless a leg states it. */
function lit(name: string, expect: string, observed: string, passed: boolean = expect === observed): Check {
  return check(name, expect, observed, passed);
}

/**
 * The shipped program as a child, so a leg exercises the binary an operator types at rather than an
 * import of its internals.
 *
 * Asynchronous on purpose: a leg that serves traffic while an erasure runs cannot block its own loop on
 * `spawnSync`, and a serving loop that is blocked serves nothing.
 */
export function shipped(cli: string, args: readonly string[]): Promise<ChildResult> {
  const command = `node ${cli} ${args.join(' ')}`;
  return new Promise<ChildResult>((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (status) => {
      resolve({ status: status ?? -1, stdout, stderr, command });
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

function firstLine(text: string): string {
  return (text.split('\n')[0] ?? '').trim();
}

function parseJson(text: string): Record<string, unknown> {
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return {};
  }
}

interface Served {
  status: number;
  receiptId: string | null;
  reason: string;
}

/**
 * One request to a served deployment, over `node:http` rather than `fetch`.
 *
 * `fetch` on this host refuses some loopback ports a raw socket reaches, and a leg that lost its verdict
 * to that refusal would be reporting the transport rather than the estate.
 */
function served(port: number, method: string, path: string, token: string | null): Promise<Served> {
  return new Promise<Served>((resolve, reject) => {
    const headers: Record<string, string> = {};
    const body = method === 'POST' ? JSON.stringify({ model: 'mock-model-1', messages: [{ role: 'user', content: 'a synthetic request for the rights exercise' }], stream: false }) : null;
    if (body !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(Buffer.byteLength(body, 'utf8'));
    }
    if (token !== null) headers['authorization'] = `Bearer ${token}`;
    const req = request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        const header = res.headers['x-ashaveri-receipt-id'];
        resolve({
          status: res.statusCode ?? 0,
          receiptId: typeof header === 'string' ? header : null,
          reason: raw.slice(0, 160).replace(/\s+/gu, ' '),
        });
      });
    });
    req.on('error', reject);
    req.end(body ?? undefined);
  });
}

/**
 * One deployment, serving, with the drill's synthetic subjects enrolled.
 *
 * The rate bounds are lifted the way the erasure-pass harness lifts them: what this drill asks is whether
 * a record lands and whether an erasure reaches it, and a request shed by a token bucket answers neither.
 */
async function bootDeployment(root: string, subjects: readonly Subject[]): Promise<{
  app: GatewayInstance;
  access: AccessLog;
  store: ReceiptStore;
  port: number;
  logDir: string;
}> {
  const logDir = join(root, 'access');
  const storeDir = join(root, 'receipts');
  mkdirSync(logDir, { recursive: true });
  mkdirSync(storeDir, { recursive: true });
  const access = new CredentialStore({
    file: { version: CREDENTIALS_FILE_VERSION, credentials: subjects.map((one) => one.record) },
    peerRate: { perMinute: 1_000_000, burst: 1_000_000 },
    allowBearer: true,
  });
  const accessLog = await openFileAccessLog({ dir: logDir, days: 184 });
  const store = await openFileReceiptStore({ dir: storeDir });
  const app = buildGateway({ access, accessLog, store });
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  return { app, access: accessLog, store, port: Number(new URL(address).port), logDir };
}

async function shutdown(booted: { app: GatewayInstance; access: AccessLog }): Promise<void> {
  await booted.app.close();
  await booted.access.close();
}

/**
 * Leg one: read out everything the estate holds for one data subject, as that subject would ask for it.
 *
 * Not built. The door that erases a subject's access-log records files a count and the bytes on both
 * sides of the removal, and it ships one sub-command; the served read path is one receipt by id, scoped
 * to the tag the presenting credential derives; the access log's own reader counts every subject's lines
 * and names none. A drill that printed a record list here would be printing a query this estate does not
 * have, and the first two rows of this leg go red the day one ships.
 */
export async function legSubjectAccess(run: Run): Promise<LegOutcome> {
  const checks: Check[] = [];
  const commands: string[] = [];
  const notes: string[] = [];
  const root = run.dir('leg1');
  const subject = syntheticSubject(1101);
  const other = syntheticSubject(1102);

  const sub = await run.shipped(['accesslog', 'export', '--access-log', root, '--credential', subject.credential, '--json']);
  commands.push(sub.command);
  checks.push(check('the erasure door answers one sub-command', 'refused as a usage error naming the one sub-command', `exit ${sub.status} ${firstLine(sub.stderr)}`, sub.status === 2 && sub.stderr.includes('expected an accesslog command: scrub')));

  const top = await run.shipped(['subject-access', '--credential', subject.credential]);
  commands.push(top.command);
  checks.push(check('the subject-access command probe is refused', 'refused as an unknown command', `exit ${top.status} ${firstLine(top.stderr)}`, top.status === 2 && top.stderr.includes("unknown command 'subject-access'")));

  const booted = await bootDeployment(root, [subject, other]);
  const asked = await served(booted.port, 'POST', '/v1/chat/completions', subject.token);
  await booted.access.drain();
  checks.push(lit('the leg issued the request it needs an id for', '200', String(asked.status), asked.status === 200));
  const ownId = await served(booted.port, 'GET', `/v1/receipts/${asked.receiptId ?? 'absent'}`, subject.token);
  checks.push(lit('the shipped read path answers one receipt by id, to its own subject', '200', String(ownId.status), ownId.status === 200));
  const foreign = await served(booted.port, 'GET', `/v1/receipts/${asked.receiptId ?? 'absent'}`, other.token);
  checks.push(check('the same id is not answerable to another subject', '404', `${foreign.status} ${foreign.reason.slice(0, 60)}`, foreign.status === 404));
  const list = await served(booted.port, 'GET', '/v1/access-log', subject.token);
  checks.push(check('the probed access-log route refuses a subject listing', 'refused before any record is read', `${list.status} ${list.reason.slice(0, 90)}`, list.status >= 400));
  const held = await booted.access.window();
  notes.push(`served on 127.0.0.1:${String(booted.port)} for two synthetic subjects`);
  notes.push(`the access-log reader the gateway itself holds answers ${JSON.stringify(held)}, which counts every subject's lines and names no subject`);
  notes.push(`a refusal that quotes no id of another tenant: ${foreign.reason.slice(0, 80)}`);
  await shutdown(booted);

  return {
    leg: 1,
    name: 'authorized subject access',
    summary: 'the probed commands and route do not provide a subject-wide read-out',
    built: false,
    verdict: 'NOT BUILT',
    checks,
    commands,
    notes,
    missing: [
      'an authorized subject read-out beyond the command and route probes exercised here',
      'the by-id receipt route is scoped to the presenting credential\'s tag, so it answers one known id and is not a read-out',
    ],
  };
}

/**
 * Leg two: erase one subject's records with nothing serving.
 *
 * The parts are the erasure-pass fixture's, so their line counts, their kept bytes and the digest the
 * rewrite has to land on are computed before the command runs rather than read out of it afterwards. Two
 * parts mix the subject with peers and with bytes no access-log reader accepts; one part holds only the
 * subject, which is the case the command answers by deleting the name.
 */
export async function legQuiesced(run: Run): Promise<LegOutcome> {
  const checks: Check[] = [];
  const commands: string[] = [];
  const notes: string[] = [];
  const dir = run.dir('leg2');
  const subject = subjectCredential(2201);
  const parts = [generatePart(0, 2211, 200 * 1024, subject), generatePart(1, 2212, 200 * 1024, subject)];
  const day = Date.parse('2026-03-01T00:00:00.000Z');
  const only = [renderLine(subject, day, 'only-1'), renderLine(subject, day + 1, 'only-2')].join('');

  const journalKept = renderLine('journal-peer', day, 'journal-peer') + '{"cred":"journal-other","note":"café"}\n' + `{"cred":"${subject}","note":"unfinished café\n`;
  const torn = `{"cred":"${subject}","note":"torn café`;
  const journals = [
    { name: 'journal-000.jsonl', before: renderLine(subject, day, 'journal-subject') + `{ "cred" : "${subject}", "written_by" : "foreign" }\n` + journalKept, after: journalKept },
    { name: 'journal-001.jsonl', before: renderLine(subject, day, 'journal-only'), after: '' },
    { name: 'journal-002.jsonl', before: renderLine(subject, day, 'journal-torn') + torn, after: `${torn}\n` },
  ];
  for (const part of parts) await writeFile(join(dir, part.name), part.bytes);
  await writeFile(join(dir, partName(2)), only);
  for (const part of journals) await writeFile(join(dir, part.name), part.before);
  const outside = `{"cred":"${subject}"}\n`;
  await writeFile(join(dir, 'access-not-a-part.jsonl'), outside);

  const removedExpect = parts.reduce((sum, each) => sum + each.subjectLines, 0) + 2 + 4;
  const keptExpect = parts.reduce((sum, each) => sum + each.keptLines, 0) + 4;
  for (const part of parts) {
    notes.push(`${part.name}: ${String(part.lines)} lines, ${String(part.subjectLines)} the subject's, ${String(part.keptLines)} kept, ${String(part.bytes.length)} bytes`);
  }
  notes.push(`${partName(2)}: 2 lines, both the subject's, so the name is deleted rather than rewritten`);

  notes.push('journal-000.jsonl mixes access records, foreign JSON and a syntax-invalid line; journal-001.jsonl holds only the subject; journal-002.jsonl ends in a torn line');
  notes.push('only access-YYYY-MM-DD-NNN.jsonl and journal-NNN.jsonl in this directory are observed; other names, stores and copies are outside this reading');
  notes.push('the torn journal line keeps its bytes with an added trailing newline; replay of these deliberately invalid journal records is not exercised');
  const volume = await readVolume(dir, subject);
  checks.push(lit('credential matches in observed files before the run', String(removedExpect), String(volume.credentialMatches)));
  checks.push(lit('strict access records naming the subject before the run', String(removedExpect - 3), String(volume.of(subject))));
  checks.push(lit('syntax-invalid lines before the run', '6', String(volume.syntaxInvalid)));
  checks.push(lit('schema-invalid JSON before the run', '4, 3 matching the credential', `${String(volume.schemaInvalid)}, ${String(volume.schemaInvalidMatches)} matching the credential`));

  const erase = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', subject, '--request', 'drill:quiesced', '--now', '2026-04-15T00:00:00Z', '--json']);
  commands.push(erase.command);
  checks.push(lit('exit status', '0', String(erase.status), erase.status === 0));
  const reported = parseJson(erase.stdout);
  checks.push(lit('records the run says it removed', String(removedExpect), String(reported['removed']), String(reported['removed']) === String(removedExpect)));
  checks.push(lit('parts the run says it worked on', '6', String(reported['files'])));
  checks.push(check('nothing was refused', 'an empty stderr', firstLine(erase.stderr), erase.stderr.trim().length === 0));

  const markerName = typeof reported['marker'] === 'string' ? (reported['marker'] as string) : '';
  const marker = parseJson(await readFile(join(dir, markerName), 'utf8').catch(() => '{}'));
  const rows = Array.isArray(marker['parts']) ? (marker['parts'] as Record<string, unknown>[]) : [];
  checks.push(lit('the marker names every part it worked on', '6', String(rows.length)));
  checks.push(lit('the marker accounts for the credential matches', String(removedExpect), String(marker['removed'])));
  checks.push(lit('the marker file total', '6', String(marker['files'])));
  const byName = new Map(rows.map((row) => [String(row['name']), row]));
  for (const part of parts) {
    const row = byName.get(part.name);
    checks.push(lit(`${part.name} before, from the disk`, `${String(part.bytes.length)}/${part.sha256}`, row === undefined ? 'absent' : `${String(row['beforeBytes'])}/${String(row['beforeSha256'])}`));
    const after = await digestOf(join(dir, part.name));
    checks.push(lit(`${part.name} after, on the disk`, `${String(part.keptBytes)}/${part.keptSha256}`, `${String(after.bytes)}/${after.sha256}`, after.present && after.bytes === part.keptBytes && after.sha256 === part.keptSha256));
    checks.push(lit(`${part.name} after, in the marker`, `${String(part.keptBytes)}/${part.keptSha256}`, `${String(row?.['afterBytes'])}/${String(row?.['afterSha256'])}`));
  }
  for (const part of [...journals, { name: partName(2), before: only, after: '' }]) {
    const row = byName.get(part.name);
    const beforeHash = createHash('sha256').update(part.before).digest('hex');
    const afterHash = createHash('sha256').update(part.after).digest('hex');
    checks.push(lit(`${part.name} before bytes and digest`, `${String(Buffer.byteLength(part.before))}/${beforeHash}`, `${String(row?.['beforeBytes'])}/${String(row?.['beforeSha256'])}`));
    checks.push(lit(`${part.name} after bytes and digest`, `${String(Buffer.byteLength(part.after))}/${afterHash}`, `${String(row?.['afterBytes'])}/${String(row?.['afterSha256'])}`));
    const after = await digestOf(join(dir, part.name));
    checks.push(check(`${part.name} exact retained bytes`, part.after.length === 0 ? 'name deleted' : 'expected bytes and digest', `${String(after.bytes)}/${after.sha256} present=${String(after.present)}`, after.present === (part.after.length > 0) && after.bytes === Buffer.byteLength(part.after) && after.sha256 === afterHash));
  }
  const markerNames = rows.map((row) => String(row['name'])).sort().join(',');
  checks.push(lit('the parts the marker names', volume.observedFiles.join(','), markerNames));
  const gone = await digestOf(join(dir, partName(2)));
  checks.push(lit(`${partName(2)} after`, `0/${EMPTY_SHA256.slice(0, 12)} at the name`, `${String(gone.bytes)}/${gone.sha256.slice(0, 12)} present=${String(gone.present)}`, gone.bytes === 0 && gone.sha256 === EMPTY_SHA256 && !gone.present));
  checks.push(lit('the marker carries the reference the operator typed', 'drill:quiesced', String(marker['request']), String(marker['request']) === 'drill:quiesced'));

  const swept = await readVolume(dir, subject);
  checks.push(lit('credential matches left in observed files', '0', String(swept.credentialMatches)));
  checks.push(lit('retained lines in observed files', String(keptExpect), String(swept.lines)));
  checks.push(lit('syntax-invalid lines retain their exact content per file', JSON.stringify(volume.syntaxInvalidLines), JSON.stringify(swept.syntaxInvalidLines)));
  checks.push(lit('schema-invalid JSON after the run', '1, 0 matching the credential', `${String(swept.schemaInvalid)}, ${String(swept.schemaInvalidMatches)} matching the credential`));
  checks.push(lit('observed credential-match decrease equals receipted removals', String(reported['removed']), String(volume.credentialMatches - swept.credentialMatches)));
  checks.push(lit('the out-of-scope name retains a credential match', outside, await readFile(join(dir, 'access-not-a-part.jsonl'), 'utf8')));

  const again = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', subject, '--now', '2026-04-15T00:00:00Z', '--json']);
  commands.push(again.command);
  const reread = parseJson(again.stdout);
  checks.push(lit('a second run over the same volume', 'exit 0 removed 0 files 0 marker null', `exit ${again.status} removed ${String(reread['removed'])} files ${String(reread['files'])} marker ${String(reread['marker'])}`, again.status === 0 && reread['removed'] === 0 && reread['files'] === 0 && reread['marker'] === null));

  return {
    leg: 2,
    name: 'quiesced erasure',
    summary: 'credential matches were removed from the observed quiesced parts and journals; retained bytes matched',
    built: true,
    verdict: 'EXERCISED',
    checks,
    commands,
    notes,
    missing: [],
    readings: { before: volume, after: swept },
  };
}

/** Live observations do not establish coordination between the scrub, journal and writer. */
export async function legCoordinated(run: Run): Promise<LegOutcome> {
  const checks: Check[] = [];
  const commands: string[] = [];
  const notes: string[] = [];
  const root = run.dir('leg3');
  const subject = syntheticSubject(3301);
  const peer = syntheticSubject(3302);
  const booted = await bootDeployment(root, [subject, peer]);
  notes.push(`serving on 127.0.0.1:${String(booted.port)}, receipts filed separately from access records`);

  const subjectIds: string[] = [];
  for (let at = 0; at < 8; at += 1) subjectIds.push((await served(booted.port, 'POST', '/v1/chat/completions', subject.token)).receiptId ?? 'none');
  const peerBefore: string[] = [];
  for (let at = 0; at < 4; at += 1) peerBefore.push((await served(booted.port, 'POST', '/v1/chat/completions', peer.token)).receiptId ?? 'none');
  await booted.access.drain();
  const before = await readVolume(booted.logDir, subject.credential);
  checks.push(lit('subject physical copies before the live scrub', '16', String(before.credentialMatches)));
  checks.push(lit('distinct subject request ids before the live scrub', '8', String(before.uniqueByCredential[subject.credential])));

  const live: Served[] = [];
  const traffic = (async (): Promise<{ firstAt: number; lastAt: number }> => {
    let firstAt = 0;
    let lastAt = 0;
    for (let at = 0; at < 24; at += 1) {
      const answer = await served(booted.port, 'POST', '/v1/chat/completions', peer.token);
      live.push(answer);
      const now = Date.now();
      if (firstAt === 0) firstAt = now;
      lastAt = now;
      await sleep(25);
    }
    return { firstAt, lastAt };
  })();
  const startedAt = Date.now();
  const erase = await run.shipped(['accesslog', 'scrub', '--access-log', booted.logDir, '--credential', subject.credential, '--request', 'drill:coordinated', '--json']);
  const finishedAt = Date.now();
  commands.push(erase.command);
  const window = await traffic;
  await booted.access.drain();

  checks.push(check('the served path was live across the erasure', 'traffic arrives between the child opening and closing', `child ${String(startedAt)}..${String(finishedAt)}, traffic ${String(window.firstAt)}..${String(window.lastAt)}`, window.firstAt >= startedAt - 100 && window.lastAt > startedAt && window.firstAt < finishedAt));
  checks.push(lit('exit status while serving', '0', String(erase.status), erase.status === 0));
  const reported = parseJson(erase.stdout);
  checks.push(lit('records the run says it removed', String(before.credentialMatches), String(reported['removed'])));

  const after = await readVolume(booted.logDir, subject.credential);
  checks.push(lit('credential matches left in observed files', '0', String(after.credentialMatches)));
  checks.push(lit('no request was shed by the erasure', '24 answers of status 200', `${String(live.length)} answers, ${String(live.filter((one) => one.status !== 200).length)} not 200`, live.length === 24 && live.every((one) => one.status === 200)));
  const receipts = live.filter((one) => one.receiptId !== null).length;
  checks.push(lit('every live answer carried a receipt id', '24', String(receipts), receipts === 24));

  const answered = peerBefore.length + live.filter((one) => one.status === 200).length;
  const onVolume = after.of(peer.credential);
  const distinct = after.uniqueByCredential[peer.credential] ?? 0;
  checks.push(check('distinct peer request ids in observed files', 'no more distinct ids than answers', `${String(distinct)} ids for ${String(answered)} answers`, distinct > 0 && distinct <= answered));
  const reconciliation = distinct === answered ? 'counts agreed this run' : `${String(answered - distinct)} fewer distinct ids than answers`;
  notes.push(`reconciliation of the peer's distinct ids against its answered requests: ${reconciliation}; ${String(onVolume)} physical copies include journals and dated parts`);
  notes.push('these are snapshot counts, not an identity-by-identity reconciliation or proof about unobserved copies; a rewritten journal can stall until restart');
  notes.push('a run that agrees does not prove the case: the loss is a window between the door\'s read and its rename, and the door says so in its own help');

  const help = await run.shipped(['--help']);
  commands.push(help.command);
  const states = help.stdout.includes('Run it against a deployment that is not serving.');
  checks.push(check('what the shipped door says about a serving deployment', 'its help tells the operator not to', `exit ${help.status}, sentence ${states ? 'present' : 'absent'}`, help.status === 0 && states));

  let own = 0;
  for (const id of subjectIds.slice(0, 3)) {
    if ((await served(booted.port, 'GET', `/v1/receipts/${id}`, subject.token)).status === 200) own += 1;
  }
  checks.push(lit('what the erasure did not reach: the erased subject still holds its own receipts', '3 of 3 fetchable by that subject', `${String(own)} of 3`, own === 3));
  let refused = 0;
  for (const id of subjectIds.slice(0, 3)) {
    if ((await served(booted.port, 'GET', `/v1/receipts/${id}`, peer.token)).status === 404) refused += 1;
  }
  checks.push(lit('and another subject cannot read them', '3 refused as 404', `${String(refused)} of 3 refused`, refused === 3));
  notes.push(`the snapshot holds ${String(after.lines)} physical lines across ${after.observedFiles.join(', ')}, of which ${String(onVolume)} strict records name the peer and ${String(after.credentialMatches)} JSON records match the erased credential`);
  await shutdown(booted);

  return {
    leg: 3,
    name: 'coordinated erasure',
    summary: 'a live scrub was observed, not a coordinated erasure or a reconciliation of all copies',
    built: false,
    verdict: 'NOT BUILT',
    checks,
    commands,
    notes,
    missing: [
      'a reconciliation between an erasure that republishes a part by rename and the writer appending to that part: the door states that a record landing between its read and its rename appears in no count and under no digest',
      'a receipt that accounts for every record the deployment answered for, so a reader can tell a cleared subject from a lost append',
    ],
  };
}

/**
 * Leg four: attempt what a hold suspends, and check that the suspension is an answer rather than a
 * sentence somebody saw once.
 *
 * Three readings, because one refusal proves little. The erasure door refuses by name and moves nothing;
 * a hold naming a different credential erases, which is the control that says the first refusal came
 * from the hold and not from the flag; and the receipts store keeps records its own window has passed and
 * reports how many a suspension is holding, so the halt is a number a peer can ask for afterwards.
 */
export async function legHoldConflict(run: Run): Promise<LegOutcome> {
  const checks: Check[] = [];
  const commands: string[] = [];
  const notes: string[] = [];
  const root = run.dir('leg4');
  const dir = join(root, 'access');
  mkdirSync(dir, { recursive: true });
  const subject = syntheticSubject(4401);
  const other = syntheticSubject(4402);
  const day = Date.parse('2026-03-01T00:00:00.000Z');
  await writeFile(join(dir, partName(0)), [renderLine(subject.credential, day, 'held-1'), renderLine(other.credential, day + 1, 'peer-1')].join(''));

  const holdPath = join(root, 'hold-named.json');
  await writeFile(holdPath, holdOver(subject.credential, 1_770_000_000));
  const before = await volumeBytes(dir);
  const refused = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', subject.credential, '--hold-record', holdPath, '--json']);
  commands.push(refused.command);
  checks.push(lit('exit status of a suspended erasure', '2', String(refused.status), refused.status === 2));
  checks.push(check('the refusal names the code and its sentence', 'HOLD_ERASURE_REFUSED: an active hold record suspends erasure of the credential this call names', firstLine(refused.stderr), refused.stderr.includes('HOLD_ERASURE_REFUSED: an active hold record suspends erasure of the credential this call names')));
  checks.push(check('and names which instruction suspends it', `credential "${subject.credential}" is under the hold issued at 1770000000 by "rights drill"`, firstLine(refused.stderr).slice(0, 240), refused.stderr.includes(`credential ${JSON.stringify(subject.credential)} is under the hold issued at 1770000000`)));
  checks.push(lit('stdout carries nothing', '', refused.stdout.trim(), refused.stdout.trim() === ''));
  const afterRefusal = await volumeBytes(dir);
  checks.push(check('bytes of the seeded access-log directory', 'unchanged', afterRefusal === before ? 'unchanged' : `moved: ${before.slice(0, 12)} to ${afterRefusal.slice(0, 12)}`, afterRefusal === before));
  const atRefusal = await readVolume(dir);
  checks.push(lit('a marker filed by the refused run', 'none', atRefusal.names.filter((name) => name.startsWith('scrub-')).join(',') || 'none', !atRefusal.names.some((name) => name.startsWith('scrub-'))));

  const otherHold = join(root, 'hold-other.json');
  await writeFile(otherHold, holdOverOther(other.credential, 1_770_000_000));
  const control = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', subject.credential, '--hold-record', otherHold, '--json']);
  commands.push(control.command);
  const controlReport = parseJson(control.stdout);
  checks.push(lit('the same erasure under a hold naming a different credential', 'exit 0, one record removed, one marker', `exit ${control.status} removed ${String(controlReport['removed'])} marker ${String(controlReport['marker'])}`, control.status === 0 && controlReport['removed'] === 1 && typeof controlReport['marker'] === 'string'));
  const discloses = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', subject.credential, '--hold-record', otherHold, '--now', '2026-04-15T00:00:00Z']);
  commands.push(discloses.command);
  checks.push(check('a hold read and found not to cover is disclosed rather than swallowed', 'the run says which bytes it weighed and that none covered the credential', `${firstLine(discloses.stdout).slice(0, 48)} / ${discloses.stdout.includes('none of the') ? 'states none covered' : 'silent'}`, discloses.status === 0 && discloses.stdout.includes('hold record(s) read') && discloses.stdout.includes('none of the')));

  const everything = join(root, 'hold-all.json');
  await writeFile(everything, holdOverEverything(1_770_000_000));
  const blanket = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', other.credential, '--hold-record', everything, '--json']);
  commands.push(blanket.command);
  checks.push(check('a hold naming no credential suspends every credential', 'exit 2 HOLD_ERASURE_REFUSED', `exit ${blanket.status} ${firstLine(blanket.stderr).slice(0, 60)}`, blanket.status === 2 && blanket.stderr.includes('HOLD_ERASURE_REFUSED')));

  const storeDir = join(root, 'receipts-held');
  mkdirSync(storeDir, { recursive: true });
  let now = 2_000_000_000;
  const clock = { name: 'drill clock', uncertaintySeconds: 0, nowSeconds: (): number => now };
  const held = await openFileReceiptStore({
    dir: storeDir,
    retention: { maxAgeSeconds: 100, time: clock },
    hold: { covers: (iat) => iat < 1_999_999_990 },
  });
  for (let at = 0; at < 5; at += 1) await held.put(`drill-held-${String(at)}`, new TextEncoder().encode(`a synthetic receipt ${String(at)}`), 1_999_999_950 + at);
  now = 2_000_000_500;
  await held.put('drill-late', new TextEncoder().encode('a synthetic receipt filed after the window passed'), now);
  const heldWindow = await held.window();
  const heldBySuspension = await held.retainedBySuspension();
  const heldChain = await held.chainState();
  notes.push(`held store: window ${JSON.stringify(heldWindow)}, retainedBySuspension ${String(heldBySuspension)}, chainState().retired ${JSON.stringify({ byAge: heldChain.retired.byAge, byCount: heldChain.retired.byCount })}`);
  checks.push(lit('records a 100s window cannot reach, kept by the hold', '6 served: 5 held and 1 inside the window', String(heldWindow.count), heldWindow.count === 6));
  checks.push(lit('the count the store reports as held', '5', String(heldBySuspension), heldBySuspension === 5));
  checks.push(lit('the held record is readable out of the served set', 'present', (await held.get('drill-held-0')) === null ? 'gone' : 'present', (await held.get('drill-held-0')) !== null));
  checks.push(lit('retirement the age bound performed', '0', String(heldChain.retired.byAge), heldChain.retired.byAge === 0));

  const unheldDir = join(root, 'receipts-unheld');
  mkdirSync(unheldDir, { recursive: true });
  await writeFile(join(unheldDir, RECEIPT_STORE_FILE), await readFile(join(storeDir, RECEIPT_STORE_FILE)));
  const unheld = await openFileReceiptStore({ dir: unheldDir, retention: { maxAgeSeconds: 100, time: clock } });
  await unheld.put('drill-late', new TextEncoder().encode('a synthetic receipt filed after the window passed'), now);
  const unheldWindow = await unheld.window();
  const unheldChain = await unheld.chainState();
  notes.push(`the same bytes with no hold handed to that opening: window ${JSON.stringify(unheldWindow)}, retired ${JSON.stringify({ byAge: unheldChain.retired.byAge, byCount: unheldChain.retired.byCount })}`);
  checks.push(lit('the control: one served, five retired by age', '1 served, 5 retired', `${String(unheldWindow.count)} served, ${String(unheldChain.retired.byAge)} retired`, unheldWindow.count === 1 && unheldChain.retired.byAge === 5));
  checks.push(lit('and the held record is gone from a store that consulted nothing', 'gone', (await unheld.get('drill-held-0')) === null ? 'gone' : 'present', (await unheld.get('drill-held-0')) === null));

  return {
    leg: 4,
    name: 'hold conflicts',
    summary: 'the held erasure left the seeded directory unchanged; the store reported held records',
    built: true,
    verdict: 'EXERCISED',
    checks,
    commands,
    notes,
    missing: [],
  };
}

/**
 * Leg five: restore a carried copy of the file the store names as the one a deployment backs up.
 *
 * What a restored copy can answer for is settled by the opening rather than by the prose around it, so
 * this leg hands the same engine four volumes: the source, a copy of the store file alone, a copy with
 * one whole record taken off the front, and a copy whose last bytes never arrived. The two damaged copies
 * are where the limits are: one is refused by name, and the other opens and reports a chain that is true
 * of fewer records than the deployment issued.
 */
export async function legRestore(run: Run): Promise<LegOutcome> {
  const checks: Check[] = [];
  const notes: string[] = [];
  const root = run.dir('leg5');
  const source = join(root, 'source');
  mkdirSync(source, { recursive: true });
  const store = await openFileReceiptStore({ dir: source });
  const ids: string[] = [];
  for (let at = 0; at < 6; at += 1) {
    const id = `drill-carried-${String(at)}`;
    ids.push(id);
    await store.put(id, new TextEncoder().encode(`a synthetic receipt body ${String(at)}`), 1_900_000_000 + at);
  }
  const headHex = Buffer.from(await store.head()).toString('hex');
  const window = await store.window();
  const sourceNames = (await readdir(source)).sort();
  const sourceCheckpoint = await readReceiptStoreCheckpoint(source);
  notes.push(`the source directory holds ${sourceNames.join(', ')}; window ${JSON.stringify(window)}; head ${headHex.slice(0, 16)}; index checkpoint ${JSON.stringify(sourceCheckpoint)}`);

  async function carry(name: string, bytes: Buffer): Promise<string> {
    const dir = join(root, name);
    mkdirSync(dir, { recursive: true });
    await writeFile(join(dir, RECEIPT_STORE_FILE), bytes);
    return dir;
  }

  const carried = await carry('copy-whole', await readFile(join(source, RECEIPT_STORE_FILE)));
  const carriedNames = (await readdir(carried)).sort();
  const indexless = await readReceiptStoreCheckpoint(carried);
  const opened = await openFileReceiptStore({ dir: carried });
  const carriedHead = Buffer.from(await opened.head()).toString('hex');
  const carriedWindow = await opened.window();
  const rebuilt = await readReceiptStoreCheckpoint(carried);
  let fetched = 0;
  for (const id of ids) {
    if ((await opened.get(id)) !== null) fetched += 1;
  }
  checks.push(lit('what a backup carries', RECEIPT_STORE_FILE, carriedNames.join(','), carriedNames.length === 1 && carriedNames[0] === RECEIPT_STORE_FILE));
  checks.push(lit('the index witness the copy arrives stating', 'none', `present=${String(indexless.present)}`, indexless.present === false));
  checks.push(lit('the chain head the copy recomputes', headHex.slice(0, 16), carriedHead.slice(0, 16), headHex === carriedHead));
  checks.push(lit('the served set the copy reports', JSON.stringify(window), JSON.stringify(carriedWindow), JSON.stringify(window) === JSON.stringify(carriedWindow)));
  checks.push(lit('every receipt fetched out of the copy', `${String(ids.length)} of ${String(ids.length)}`, `${String(fetched)} of ${String(ids.length)}`, fetched === ids.length));
  checks.push(check('what an index witness is worth on a copy', 'the first opening rebuilds it from the bytes and states the head it recomputed', `present=${String(rebuilt.present)}, head ${rebuilt.head.slice(0, 16)}`, rebuilt.present === true && rebuilt.head === carriedHead));
  notes.push(`the source directory holds ${sourceNames.join(', ')}; its own window ${JSON.stringify(window)}; head ${headHex.slice(0, 16)}; readReceiptStoreCheckpoint before any further opening answers ${JSON.stringify(sourceCheckpoint)}`);
  notes.push(`a restored copy states a chain recomputed from its own bytes and an anchor it states itself; the directory it was written into holds ${RECEIPT_STORE_FILE} alone, where the source holds the index and the owner claim beside it, so nothing in the copy names the process or the volume that wrote it, and its agreement with a deployment is a figure a reader has to hold apart from the copy`);

  const bytes = await readFile(join(source, RECEIPT_STORE_FILE));
  const short = await carry('copy-prefix-missing', bytes.subarray(4 + bytes.readUInt32BE(0)));
  const shortOpening = await openFileReceiptStore({ dir: short }).then(
    () => ({ opened: true, refusal: '' }),
    (error: unknown) => ({ opened: false, refusal: error instanceof Error ? error.message : String(error) }),
  );
  checks.push(check('a copy missing one whole record from the front', 'refused before it serves anything', shortOpening.opened ? 'opened' : shortOpening.refusal.slice(0, 120), !shortOpening.opened && shortOpening.refusal.includes('STORE_CHAIN_BROKEN')));

  const cut = await carry('copy-tail-cut', bytes.subarray(0, bytes.length - 3));
  const cutStore = await openFileReceiptStore({ dir: cut });
  const cutHead = Buffer.from(await cutStore.head()).toString('hex');
  const cutWindow = await cutStore.window();
  checks.push(lit('a copy whose last bytes never arrived', `${String(window.count - 1)} served, one fewer than the source`, `${String(cutWindow.count)} served`, cutWindow.count === window.count - 1));
  checks.push(check('what the interrupted copy can be told by', 'a head that differs from the pinned one, and nothing inside the copy', `head ${cutHead.slice(0, 12)} against ${headHex.slice(0, 12)}`, cutHead !== headHex));
  notes.push('the store repaired the partial tail record rather than refusing it, which is the documented reading of an append that never finished and the same reading of a copy that never finished');

  return {
    leg: 5,
    name: 'backup restoration',
    summary: 'a carried copy re-proves its chain and proves nothing about its own completeness',
    built: true,
    verdict: 'EXERCISED',
    checks,
    commands: ['openFileReceiptStore over a directory holding a copied receipts.log, and readReceiptStoreCheckpoint over the same'],
    notes,
    missing: [],
  };
}

/** A bounded source sample: top-level package sources and four gateway files, not recursive. */
async function shippedSources(): Promise<string[]> {
  const root = fileURLToPath(new URL('../../../..', import.meta.url));
  const found: string[] = [];
  for (const pkg of await readdir(join(root, 'packages'))) {
    const src = join(root, 'packages', pkg, 'src');
    let names: string[];
    try {
      names = await readdir(src);
    } catch {
      // A workspace member with no `src` holds no shipped code to read.
      continue;
    }
    for (const name of names.sort()) {
      if (name.endsWith('.ts')) found.push(join(src, name));
    }
  }
  for (const name of ['server.ts', 'cli.ts', 'access.ts', 'aclog.ts']) {
    found.push(join(root, 'gateway', 'src', name));
  }
  return found;
}

/** The marker and limits disclose no notification evidence; a lexical sample cannot prove absence. */
export async function legNotification(run: Run): Promise<LegOutcome> {
  const checks: Check[] = [];
  const commands: string[] = [];
  const notes: string[] = [];
  const files = await shippedSources();
  const declarations: string[] = [];
  const otherMentions: string[] = [];
  for (const path of files) {
    const text = await readFile(path, 'utf8').catch(() => '');
    text.split('\n').forEach((line, index) => {
      if (!/notif/iu.test(line)) return;
      const name = (path.split(/[\\/]/u).pop() ?? path) + ':' + String(index + 1);
      if (/^\s*(?:export\s+)?(?:async\s+)?(?:function|const|class|interface|type)\s+\w*notif/iu.test(line)) declarations.push(name);
      else otherMentions.push(name);
    });
  }
  checks.push(lit('notification-named declarations matched in the source sample', '0', `${String(declarations.length)} ${declarations.join(', ')}`, declarations.length === 0));
  checks.push(check('other notification mentions in the source sample', 'at least one lexical match', `${String(otherMentions.length)} mentions in ${String(files.length)} sampled files`, otherMentions.length > 0));
  notes.push('source sample: top-level packages/*/src/*.ts and gateway/src/{server,cli,access,aclog}.ts only; nested sources and other gateway files are not scanned');
  notes.push('the line regex recognizes only certain declaration spellings; other mentions are not classified as prose, and zero matches is not universal evidence of absence');

  const dir = run.dir('leg6');
  const subject = syntheticSubject(6601);
  const holdPath = join(dir, 'hold.json');
  await writeFile(join(dir, partName(0)), renderLine(subject.credential, Date.parse('2026-03-01T00:00:00.000Z'), 'notify-probe'));
  await writeFile(holdPath, holdOverOther(subjectCredential(6602), 1_770_000_000));
  const erase = await run.shipped(['accesslog', 'scrub', '--access-log', dir, '--credential', subject.credential, '--hold-record', holdPath, '--request', 'drill:notification-probe', '--now', '2026-04-15T00:00:00Z', '--json']);
  commands.push(erase.command);
  const markerName = String(parseJson(erase.stdout)['marker'] ?? '');
  const marker = parseJson(await readFile(join(dir, markerName), 'utf8').catch(() => '{}'));
  checks.push(lit('what an erasure receipts, member by member', 'credential,files,parts,removed,request,t', Object.keys(marker).sort().join(','), Object.keys(marker).sort().join(',') === 'credential,files,parts,removed,request,t'));
  notes.push(`an erasure ran, filed a marker, and stated nothing about a notification: removed ${String(parseJson(erase.stdout)['removed'])} in ${String(parseJson(erase.stdout)['files'])} file(s), marker ${markerName}`);
  notes.push(`hold record limits, verbatim: ${HOLD_RECORD_LIMITS}`);
  notes.push(`incident bundle limits, verbatim: ${INCIDENT_BUNDLE_LIMITS}`);

  return {
    leg: 6,
    name: 'processor notification',
    summary: 'no notification was exercised; the marker and two limits provide no notification evidence',
    built: false,
    verdict: 'NOT BUILT',
    checks,
    commands,
    notes,
    missing: [
      'a notification to the other party to a processing arrangement when an erasure lands or a hold suspends one',
      'a member of the erasure receipt recording a notification as sent, due, or owed',
    ],
  };
}

/** The host the record names, so a figure can be attributed to a machine. */
export function hostLine(): string {
  return `node ${process.version}, ${release()}, ${String(cpus().length)} cpus, clock source ${HOST_CLOCK_SOURCE.name}`;
}
