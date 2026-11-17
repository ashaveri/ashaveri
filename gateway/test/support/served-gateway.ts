import { createHash } from 'node:crypto';
import { noteSpawn } from './spawn-budget.js';
import { spawn } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  randomNonce,
  signPopAuthorization,
  toBase64Url,
  type PopFields,
} from '@ashaveri/receipt';

/**
 * Booting the built gateway as a child process, asking it over HTTP, and stopping it again.
 *
 * This is the helper `gateway/test/cli.test.ts` grew case by case, held in one file so a second suite that
 * serves a real deployment boots the same way rather than writing its own. Two things make one copy worth
 * having: a boot that leaves a child behind poisons the machine for the suites that follow it, and a boot
 * that resolves on a half-written listening line aims its requests at a number nothing holds. Both are
 * failures of the helper rather than of any one case, so they are fixed once here.
 *
 * The deadlines are exported too, because a case's ceiling has to be read off the patience its own
 * processes were given. `test/support/spawn-guard.ts` refuses a case bounded below that sum.
 */

const CLI = fileURLToPath(new URL('../../dist/cli.js', import.meta.url));

/**
 * The two waits a case can spend, named once because a case's ceiling has to be read off them.
 *
 * `SPAWN_DEADLINE_MS` bounds one command that is expected to exit by itself; `BOOT_DEADLINE_MS` bounds one
 * gateway that is expected to print its banner. A ceiling below the sum of a case's calls and their own
 * deadlines is a ceiling that fires first, and what it reports is the runner's timeout rather than the named
 * failure the deadline exists to produce. So `budgetFor` states the arithmetic, and every case that spawns
 * or boots passes its count through it: the worst case is what a hang costs, and a hang is a defect worth
 * waiting for once rather than misreading.
 *
 * A boot also picks its port before it starts a child, and `readPortState` below asks its two questions
 * of the port the boot printed, so `bootBudget` carries `PREFLIGHT_BUDGET_MS` beside the boots it is
 * named for: a boot that spends that preflight is a boot the case is still waiting on, and the ceiling
 * has to be read off the arithmetic rather than guessed at.
 */
export const SPAWN_DEADLINE_MS = 8_000;
export const BOOT_DEADLINE_MS = 10_000;
/**
 * How many candidates `walkToAddressablePort` will look at before it names them as its own failure. The
 * road this bounds is a machine whose HTTP client turns down a run of neighbouring ports; it is not a
 * count of how often the helper asks the same question again, because nothing here does that.
 */
export const PORT_CANDIDATES = 8;
/** How long either preflight question waits. A loopback answer arrives in milliseconds on any machine, so
 *  this is slack for a machine that is not answering, not an estimate of how long answering takes. */
export const PROBE_DEADLINE_MS = 1_000;
/** What one boot can spend on its preflight: the walk, two bounded questions per candidate, and the two
 *  questions `readPortState` asks of the port the boot printed. */
export const PREFLIGHT_BUDGET_MS = (PORT_CANDIDATES + 1) * 2 * PROBE_DEADLINE_MS;
export const budgetFor = (calls: number, deadline: number): number => calls * deadline + 2_000;
export const spawnBudget = (calls: number): number => budgetFor(calls, SPAWN_DEADLINE_MS);
export const bootBudget = (boots: number): number => budgetFor(boots, BOOT_DEADLINE_MS) + boots * PREFLIGHT_BUDGET_MS;
/** The ceiling for a case that runs the walk without booting anything: every candidate with its two
 *  questions, plus `extra` further bounded questions the case asks around the walk. */
export const pickBudget = (extra: number): number => budgetFor(PORT_CANDIDATES * 2 + extra, PROBE_DEADLINE_MS);

/** How long a request that got no answer waits for the exit event before it describes the child. */
const DEPARTURE_SETTLE_MS = 250;

/**
 * A gateway `bootServing` booted and left listening, and the two things a case can do to it.
 *
 * `reached` is for the question a request that got no answer cannot answer for itself: whether the
 * process that printed the listening line still holds that port, and if it does not, how it went away
 * and what it printed on the way out. A `TypeError: fetch failed` carries none of that, and the two
 * readings a case would otherwise have to guess between, a start that went away behind its own banner
 * and a port the client refuses before it opens a socket, look alike without it.
 */
export interface ServedGateway {
  readonly port: number;
  readonly kill: () => Promise<void>;
  readonly reached: () => Promise<string>;
}

/** What the HTTP client of a process that will not address a port answers with, in its own words. */
const CLIENT_REFUSAL = /bad port/iu;

/**
 * What a port a listening line named can be, as the two questions that can tell the states apart name
 * them.
 *
 * `usable` is the state every case has always taken: a port this client will address. `gateway gone` is
 * the child that printed the listening line and then left the port it named, which is the reading a case
 * already gets from `ask` and `kill`, so nothing here stops it and nothing here says it first.
 * `client refuses` is the third: the port is bound, still held, and turned down by the HTTP client in
 * this very process before that client opens a socket, so no request the case makes over it can reach
 * anything. That state is somebody's port choice, and it is the only one a boot stops on.
 */
type PortState =
  | { readonly state: 'usable' }
  | { readonly state: 'gateway gone' }
  | { readonly state: 'client refuses'; readonly answer: string };

/**
 * Whether the HTTP client in this process can address `port` at all, with its own words for the answer.
 *
 * Asked at `127.0.0.2`, which no gateway booted here binds: each one is started on the address its
 * banner names, and that banner line is what the boot matches before it asks anything. A refusal is a
 * decision about the port alone, measured as the same `bad port` at 127.0.0.1, at 127.0.0.2 and at ::1
 * for one refused port, so asking away from the gateway loses nothing. Asking at it would cost something:
 * a request that reaches a running gateway is answered by the same pipeline a case's request goes
 * through, measured as one line written to the access log the boot points at and one token taken off the
 * `--peer-rate` burst a bound case pins.
 */
export async function askClientAboutPort(port: number): Promise<{ readonly refuses: boolean; readonly answer: string }> {
  try {
    const response = await fetch(`http://127.0.0.2:${String(port)}/`, { signal: AbortSignal.timeout(PROBE_DEADLINE_MS) });
    await response.body?.cancel();
    return { refuses: false, answer: `answered ${String(response.status)}` };
  } catch (error) {
    const answer = connectionReason(error);
    return { refuses: CLIENT_REFUSAL.test(answer), answer };
  }
}

/**
 * Whether the address the listening line named still answers a connection, asked of the socket layer and
 * not of the HTTP client. The client is the thing under question above, so it cannot answer whether the
 * gateway is there; a raw connection is answered by a gateway that is standing without handing it a
 * request to parse, which is measured as writing nothing and spending nothing.
 */
function askSocketAboutPort(port: number): Promise<string> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port }, () => {
      socket.destroy();
      resolve('connected');
    });
    const settle = (answer: string): void => {
      socket.destroy();
      resolve(answer);
    };
    socket.once('error', (error) => settle(errnoReason(error)));
    socket.setTimeout(PROBE_DEADLINE_MS, () => settle(`no answer within ${String(PROBE_DEADLINE_MS)}ms`));
  });
}

/**
 * The state of a port a boot printed, read by asking each of the two layers the one question it can
 * answer, in the order that costs the gateway nothing.
 */
async function readPortState(port: number): Promise<PortState> {
  const asked = await askClientAboutPort(port);
  if (!asked.refuses) return { state: 'usable' };
  // A port the client turns down is somebody's port choice only while there is still a gateway standing
  // on it. Without that second answer the road is a start that left behind its listening line, and
  // stopping on the refusal would hide it: the case reads that from `ask` and `kill`.
  return (await askSocketAboutPort(port)) === 'connected'
    ? { state: 'client refuses', answer: asked.answer }
    : { state: 'gateway gone' };
}

/**
 * Whether this process can have `port` on `127.0.0.1` for the length of a moment, asked by binding it
 * with a listener that never accepts a connection and letting go again before this answers.
 *
 * Asked with `0` this is the operating system's own question, and the port the listener reports back is
 * the lowest one the machine allows, which is the number `--port 0` would have printed. Asked with a
 * number it is a check that the walk is not about to hand the gateway a port another process already
 * holds. Nothing ever connects to either listener, so the road out leaves no socket behind, and the port
 * is whoever wants it next as soon as the caller is told.
 */
export function bindPortBriefly(port: number): Promise<{ readonly bound: boolean; readonly port: number; readonly answer: string }> {
  return new Promise((resolve) => {
    const listener = createServer();
    // On one object rather than a bare `const`, so `settle` can clear the deadline whichever road it is
    // called from without either side reading a binding that is not there yet.
    const held: { deadline?: NodeJS.Timeout } = {};
    const settle = (bound: boolean, at: number, answer: string): void => {
      if (held.deadline !== undefined) clearTimeout(held.deadline);
      // The close is what hands the port back. A listener that failed to open has no error to be left
      // sitting on, and `close` on one is answered by this handler rather than by a callback.
      listener.removeAllListeners('error');
      listener.close();
      resolve({ bound, port: at, answer });
    };
    held.deadline = setTimeout(() => settle(false, port, `no bind within ${String(PROBE_DEADLINE_MS)}ms`), PROBE_DEADLINE_MS);
    listener.once('error', (error) => settle(false, port, errnoReason(error)));
    listener.listen({ host: '127.0.0.1', port }, () => {
      const address = listener.address();
      settle(true, typeof address === 'object' && address !== null ? address.port : port, 'bound');
    });
  });
}

/**
 * The walk the port pick runs, from `start`, and the arm the case that measures it puts in front of a port
 * it can measure.
 *
 * Each candidate answers two questions, in the order that costs a gateway no request: whether this
 * process's HTTP client will address the port at all, and whether the socket layer will hand that port
 * to this process for a moment. A client that refuses the number does it as a decision about the number
 * alone, measured as the same `bad port` at every loopback address, so the walk turns a refused
 * candidate down without binding it and never holds a port it means to give back. The bind is asked only
 * of a candidate the client will address, because that is the moment the port is about to be chosen, and
 * a candidate that will not bind is turned down for the same reason: the gateway has to be able to take
 * it after this helper lets go.
 *
 * The step is `start + 1` and not a second ask of the operating system, because a second ask is the same
 * ask: the machine hands out the lowest port it allows, and letting go of that port leaves it the lowest
 * port it allows, so asking again answers with the number that was just turned down. A walk that re-asked
 * would be a retry standing in for the one thing it cannot retry, which is which number the machine
 * allows, and the step is what makes the question answerable at all.
 */
export async function walkToAddressablePort(start: number): Promise<number> {
  const tried: string[] = [];
  for (let step = 0; step < PORT_CANDIDATES; step += 1) {
    const candidate = start + step;
    const asked = await askClientAboutPort(candidate);
    if (asked.refuses) {
      tried.push(`port ${String(candidate)}: the client answered ${asked.answer}`);
      continue;
    }
    const held = await bindPortBriefly(candidate);
    if (!held.bound) {
      tried.push(`port ${String(candidate)}: the client answered ${asked.answer}, then the bind answered ${held.answer}`);
      continue;
    }
    return candidate;
  }
  throw new Error(
    `none of the ${String(PORT_CANDIDATES)} ports from ${String(start)} is a port this test process can boot a gateway on, ` +
      `which is two questions about one number: its HTTP client has to address the port and its socket layer has to hand it over. ` +
      `This tried ${tried.join('; ')}`,
  );
}

/**
 * The port the next boot binds, chosen and proved addressable before any child starts.
 *
 * Every case that speaks HTTP to a booted gateway aims at the port the gateway's banner names, so a boot
 * on a port this process's own HTTP client refuses is a boot no case can read: the request dies with the
 * client's refusal before it opens a socket while the gateway stands there serving it. Choosing before
 * starting is what keeps that state out of a suite, and it costs one bound-and-released port and one
 * client question, both of which answer in milliseconds on a machine that is answering at all.
 */
export async function pickAddressablePort(): Promise<number> {
  const handed = await bindPortBriefly(0);
  if (!handed.bound) {
    throw new Error(`the operating system would not hand this process a port to ask about (it answered ${handed.answer})`);
  }
  return await walkToAddressablePort(handed.port);
}

/**
 * Start a gateway that serves, and stop it. `bootToListeningLine` resolves on the listening line, which
 * names the port the gateway bound, and hands back a `kill` that waits for the exit event, so a case
 * cannot leave a child or its socket behind.
 *
 * The port comes from `pickAddressablePort` rather than from leaving the choice to the child, and it is
 * the second question's answer that gets it there: a port the client of this process will not address is
 * turned down before a gateway is asked to stand on it. A case that names its own `--port` still wins,
 * because the later of the two flags a boot carries is the one the gateway reads, and what such a case
 * names is its own business: `readPortState` asks its two questions of the port the banner printed, and
 * the one state that is a port choice rather than a child that went away stops the boot.
 *
 * Every other reading keeps what it has, so no exit and no timeout is turned into anything else.
 *
 * Resolving on that line leaves one window a boot does not police: a child that printed it can still go
 * away before the case asks it for anything, and the case then reads a fetch error about a port nobody
 * holds. So the child's state is kept in `bootToListeningLine` instead of inferred downstream. `kill`
 * fails a case whose child left of its own accord after it said it was listening, `reached` says where
 * that child got to, and `ask` below puts both into the request that got no answer. The stderr a boot
 * produces is kept rather than drained and thrown away, because it is where a gateway that is about to
 * stop says why.
 */
export async function bootServing(args: string[]): Promise<ServedGateway> {
  const picked = await pickAddressablePort();
  const served = await bootToListeningLine(picked, args);
  const state = await readPortState(served.port);
  if (state.state !== 'client refuses') return served;
  const refusal =
    `the gateway listened on port ${String(served.port)} and this test process's HTTP client refuses that port before it opens a socket ` +
    `(${state.answer}); ${served.port === picked ? 'this helper picked that port' : 'the case named that port after this helper picked one'}, ` +
    `and this helper refuses to boot on a port its own client will not address, because no request this suite makes over such a port ` +
    `ever opens a socket. The boot carried [--mock --port ${String(picked)} ${args.join(' ')}]`;
  try {
    await served.kill();
  } catch (departure) {
    // A child that left while this was being read is a second fact about the same boot, and the refusal
    // is the one the case is about, so the refusal is named and the departure rides as its cause.
    throw new Error(refusal, { cause: departure });
  }
  throw new Error(refusal);
}

/** The prefix the gateway's own banner gives its listening line, spelled as `gateway/src/cli.ts` writes it. */
export const LISTENING_PREFIX = 'signerd (mock) listening on ';

/** The whole of what a boot reads off that line: the port the child says it bound. */
export const LISTENING_PORT = /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:([1-9]\d*)\s*$/u;

/**
 * The listening line in the stdout a boot has read so far, or `undefined` where that buffer carries no
 * terminated one.
 *
 * The segment behind the last newline is a line still being written, so it is no candidate: `LISTENING_PORT`
 * answers a prefix of a port's digits as a port, and a boot that resolved on one would aim its case at a
 * number nothing holds and report a connection refused where the fault was in the reading.
 */
export function listeningLine(out: string): string | undefined {
  const lines = out.split('\n');
  if (!out.endsWith('\n')) lines.pop();
  return lines.find((each) => each.startsWith(LISTENING_PREFIX));
}

/**
 * One boot: start the gateway on `port`, read the listening line that names the port it bound, and hand
 * back that child with the two things a case can do to it. The port the banner named is what the case
 * aims at, and a banner naming a port this boot never asked for is a banner this helper cannot aim
 * anything at, so it is refused rather than read. Every road out of here that does not hand a child back
 * stops it first, so a start that never printed, printed a line naming no port, or named a port it was
 * not asked for leaves no process and no socket behind.
 */
export async function bootToListeningLine(port: number, args: string[]): Promise<ServedGateway> {
  noteSpawn(BOOT_DEADLINE_MS);
  // The port this boot asked for, which is the later of two `--port` flags where a case names its own,
  // because the later of the two is the one the gateway reads.
  const askedFlag = args.lastIndexOf('--port');
  const asked = askedFlag === -1 ? port : Number(args[askedFlag + 1]);
  const env = { ...process.env };
  delete env['DSTACK_SIMULATOR_ENDPOINT'];
  const child = spawn(process.execPath, [CLI, '--mock', '--port', String(port), ...args], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  let err = '';
  // The two facts a departure is made of: how the child went, and whether this helper was the one that
  // asked. `undefined` while it is listening.
  let departed: { readonly exit: string; readonly asked: boolean } | undefined;
  let asking = false;
  // The port the listening line named. It stands for whether the child ever said it was listening, which
  // is the difference between an exit to name as a start that never served and an exit to name as a
  // gateway that left after it promised a port, and it is the number a request was aimed at.
  let bound: number | undefined;
  const stopped = new Promise<void>((resolve) => {
    child.once('exit', (code, signal) => {
      departed = { exit: signal === null ? `exit code ${String(code)}` : `signal ${signal}`, asked: asking };
      resolve();
    });
  });

  /** The child, as far as this helper can tell it: whether it is there, and what it printed. */
  async function reached(): Promise<string> {
    // A refused connection and the exit event are in flight together at the moment a child goes away, so
    // this waits for whichever of the two arrives first, up to a short settle. The sentence then says the
    // child had gone, rather than that this helper had not yet been told of it.
    await Promise.race([stopped, new Promise((resolve) => setTimeout(resolve, DEPARTURE_SETTLE_MS))]);
    const where =
      departed === undefined
        ? 'was still running when this was read'
        : `had gone with ${departed.exit}${departed.asked ? ', after this helper asked for the kill' : ', of its own accord'}`;
    return (
      `the gateway this helper started as pid ${String(child.pid)} with [--mock --port ${String(port)} ${args.join(' ')}] ` +
      `${where}. The port its listening line named, and the one this request was aimed at, is ${String(bound)}. ` +
      `Its stderr held ${JSON.stringify(err)} and the first line of its stdout held ${JSON.stringify(out.split('\n')[0] ?? '')}`
    );
  }

  const kill = async (): Promise<void> => {
    asking = true;
    child.kill('SIGKILL');
    await stopped;
    if (bound !== undefined && departed !== undefined && !departed.asked) {
      throw new Error(`the gateway exited after it printed its listening line and before this helper stopped it; ${await reached()}`);
    }
  };
  try {
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      err += chunk;
    });
    const printed = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`no listening line within ${String(BOOT_DEADLINE_MS / 1_000)}s; stdout held ${JSON.stringify(out)}`)),
        BOOT_DEADLINE_MS,
      );
      const giveUp = (message: string): void => {
        clearTimeout(timer);
        reject(new Error(`${message}; stdout held ${JSON.stringify(out)}`));
      };
      child.once('error', (error) => giveUp(`the gateway failed to spawn: ${error.message}`));
      child.once('exit', (code) => giveUp(`the gateway exited with ${String(code)} before it listened`));
      child.stdout.on('data', (chunk: string) => {
        out += chunk;
        const line = listeningLine(out);
        if (line === undefined) return;
        const named = LISTENING_PORT.exec(line);
        if (named?.[1] === undefined) {
          giveUp(`the listening line names no bound port: ${line}`);
          return;
        }
        bound = Number(named[1]);
        if (bound !== asked) {
          giveUp(
            `the listening line names port ${String(bound)} and this boot asked the gateway for ${String(asked)} ` +
              `with [--mock --port ${String(port)} ${args.join(' ')}]: ${line}`,
          );
          return;
        }
        clearTimeout(timer);
        resolve(bound);
      });
    });
    return { port: printed, kill, reached };
  } catch (error) {
    await kill();
    throw error;
  }
}

/**
 * One request to a gateway `bootServing` booted, and a failure that names the child it aimed at.
 *
 * A connection that reaches nothing arrives as `TypeError: fetch failed`, which says neither the port it
 * was aimed at nor the reason the stack gave, and a case read on a runner cannot go and ask the child. The
 * three facts that tell a start which left after it printed its listening line apart from a port the
 * client refuses before it opens a socket are the port, the reason the connection carried, and whether the
 * process is still there to be carried by, so the failure is rebuilt out of those. The original error
 * stays as the cause, which is what keeps the fetch's own stack in the report.
 */
export async function ask(served: ServedGateway, target: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(`http://127.0.0.1:${String(served.port)}${target}`, init);
  } catch (error) {
    throw new Error(`no answer at ${target}: ${connectionReason(error)}; ${await served.reached()}`, { cause: error });
  }
}

/** The reason a connection failed, as the layer under `fetch` spelled it, since `fetch failed` never does. */
export function connectionReason(error: unknown): string {
  const cause = error instanceof Error ? error.cause : undefined;
  if (!(cause instanceof Error)) return String(error);
  return errnoReason(cause);
}

/** An errno's own sentence, then its code, because the sentence alone is spelled differently on every
 *  platform while the code is not. */
export function errnoReason(error: Error): string {
  const code = (error as NodeJS.ErrnoException).code;
  return `${error.message}${code === undefined ? '' : ` (${code})`}`;
}

/**
 * One completion, and the two things a caller can branch on, against a booted process. A case that asks
 * what a flag does to a served completion is why this sits beside the boot rather than under one suite.
 */
export const COMPLETION = '{"model":"mock-model-1","messages":[{"role":"user","content":"guard"}]}';

export interface ServedCompletion {
  readonly status: number;
  readonly code: string | undefined;
  readonly receiptId: string | null;
  readonly text: string;
}

export async function complete(
  served: ServedGateway,
  pop: { record: { id: string }; privateKey: Uint8Array },
): Promise<ServedCompletion> {
  const nonce = randomNonce();
  return sendCompletion(served, pop, nonce);
}

/**
 * One completion sent with the nonce a caller names.
 *
 * `complete` above draws its own, which is what a case that only wants a served receipt needs. A case
 * about a retry needs the nonce to be the fact it varies: the same one twice is a replay the intake
 * refuses, a fresh one over the same body is a retry the intake serves again.
 */
export async function sendCompletion(
  served: ServedGateway,
  pop: { record: { id: string }; privateKey: Uint8Array },
  nonce: Uint8Array,
): Promise<ServedCompletion> {
  const fields: PopFields = {
    ts: Math.floor(Date.now() / 1000),
    nonce,
    method: 'POST',
    target: '/v1/chat/completions',
    bodyDigestHex: createHash('sha256').update(COMPLETION).digest('hex'),
  };
  const response = await ask(served, '/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
      'x-ashaveri-nonce': toBase64Url(nonce),
    },
    body: COMPLETION,
  });
  const text = await response.text();
  return {
    status: response.status,
    code: (JSON.parse(text) as { error?: { code?: string } }).error?.code,
    receiptId: response.headers.get('x-ashaveri-receipt-id'),
    text,
  };
}

/** A served completion has to answer 200 and name a receipt, or the drill has no acknowledgement to work from. */
export function assertAcknowledged(answer: ServedCompletion, what: string): string {
  expect(answer.status, `${what}: ${answer.text}`).toBe(200);
  expect(answer.receiptId, `${what}: no receipt id on the answer`).toBeTypeOf('string');
  return answer.receiptId as string;
}

/**
 * One signed read of a served route, and its body as text.
 *
 * The documents a drill reads off a live deployment - its manifest, and the receipt behind an id - are
 * behind the same floor as a completion, so the presentation is built here rather than at each caller.
 */
export async function signedGet(
  served: ServedGateway,
  pop: { record: { id: string }; privateKey: Uint8Array },
  target: string,
): Promise<{ status: number; body: string }> {
  const nonce = randomNonce();
  const fields: PopFields = {
    ts: Math.floor(Date.now() / 1000),
    nonce,
    method: 'GET',
    target,
    bodyDigestHex: EMPTY_BODY_SHA256_HEX,
  };
  const response = await ask(served, target, {
    headers: {
      authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
      'x-ashaveri-nonce': toBase64Url(nonce),
    },
  });
  return { status: response.status, body: await response.text() };
}
