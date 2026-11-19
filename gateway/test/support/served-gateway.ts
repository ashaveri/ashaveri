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

const CLI = fileURLToPath(new URL('../../dist/cli.js', import.meta.url));

// Shared ceilings let spawn-guard check each test's worst-case wait.
export const SPAWN_DEADLINE_MS = 8_000;
export const BOOT_DEADLINE_MS = 10_000;
export const PORT_CANDIDATES = 8;
const PROBE_DEADLINE_MS = 1_000;
export const PREFLIGHT_BUDGET_MS = (PORT_CANDIDATES + 1) * 2 * PROBE_DEADLINE_MS;
export const budgetFor = (calls: number, deadline: number): number => calls * deadline + 2_000;
export const spawnBudget = (calls: number): number => budgetFor(calls, SPAWN_DEADLINE_MS);
export const bootBudget = (boots: number): number => budgetFor(boots, BOOT_DEADLINE_MS) + boots * PREFLIGHT_BUDGET_MS;
export const pickBudget = (extra: number): number => budgetFor(PORT_CANDIDATES * 2 + extra, PROBE_DEADLINE_MS);
const DEPARTURE_SETTLE_MS = 250;

export interface ServedGateway {
  readonly port: number;
  readonly kill: () => Promise<void>;
  readonly reached: () => Promise<string>;
}

const CLIENT_REFUSAL = /bad port/iu;
type PortState =
  | { readonly state: 'usable' }
  | { readonly state: 'gateway gone' }
  | { readonly state: 'client refuses'; readonly answer: string };

// Probe away from the gateway so preflight spends no rate token or access-log line.
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

// A raw connection distinguishes a held port from a departed child without sending HTTP.
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

async function readPortState(port: number): Promise<PortState> {
  const asked = await askClientAboutPort(port);
  if (!asked.refuses) return { state: 'usable' };
  return (await askSocketAboutPort(port)) === 'connected'
    ? { state: 'client refuses', answer: asked.answer }
    : { state: 'gateway gone' };
}

export function bindPortBriefly(port: number): Promise<{ readonly bound: boolean; readonly port: number; readonly answer: string }> {
  return new Promise((resolve) => {
    const listener = createServer();
    const held: { deadline?: NodeJS.Timeout } = {};
    const settle = (bound: boolean, at: number, answer: string): void => {
      if (held.deadline !== undefined) clearTimeout(held.deadline);
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

// Walking forward avoids receiving the same unusable ephemeral port again.
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

export async function pickAddressablePort(): Promise<number> {
  const handed = await bindPortBriefly(0);
  if (!handed.bound) {
    throw new Error(`the operating system would not hand this process a port to ask about (it answered ${handed.answer})`);
  }
  return await walkToAddressablePort(handed.port);
}

// Refuse an unaddressable port while preserving unrelated child-exit diagnostics.
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
    throw new Error(refusal, { cause: departure });
  }
  throw new Error(refusal);
}

export const LISTENING_PREFIX = 'signerd (mock) listening on ';
export const LISTENING_PORT = /^signerd \(mock\) listening on http:\/\/127\.0\.0\.1:([1-9]\d*)\s*$/u;

// An unterminated banner may hold only a prefix of the port's digits.
export function listeningLine(out: string): string | undefined {
  const lines = out.split('\n');
  if (!out.endsWith('\n')) lines.pop();
  return lines.find((each) => each.startsWith(LISTENING_PREFIX));
}

export async function bootToListeningLine(port: number, args: string[]): Promise<ServedGateway> {
  noteSpawn(BOOT_DEADLINE_MS);
  // The CLI gives the last flag precedence.
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
  let departed: { readonly exit: string; readonly asked: boolean } | undefined;
  let asking = false;
  let bound: number | undefined;
  const stopped = new Promise<void>((resolve) => {
    child.once('exit', (code, signal) => {
      departed = { exit: signal === null ? `exit code ${String(code)}` : `signal ${signal}`, asked: asking };
      resolve();
    });
  });

  async function reached(): Promise<string> {
    // A refused connection can arrive just ahead of the child's exit event.
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

// Fetch's bare connection error omits the child state needed to diagnose a failed boot.
export async function ask(served: ServedGateway, target: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(`http://127.0.0.1:${String(served.port)}${target}`, init);
  } catch (error) {
    throw new Error(`no answer at ${target}: ${connectionReason(error)}; ${await served.reached()}`, { cause: error });
  }
}

export function connectionReason(error: unknown): string {
  const cause = error instanceof Error ? error.cause : undefined;
  if (!(cause instanceof Error)) return String(error);
  return errnoReason(cause);
}

export function errnoReason(error: Error): string {
  const code = (error as NodeJS.ErrnoException).code;
  return `${error.message}${code === undefined ? '' : ` (${code})`}`;
}

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

export function assertAcknowledged(answer: ServedCompletion, what: string): string {
  expect(answer.status, `${what}: ${answer.text}`).toBe(200);
  expect(answer.receiptId, `${what}: no receipt id on the answer`).toBeTypeOf('string');
  return answer.receiptId as string;
}

export async function signedGet(
  served: ServedGateway,
  pop: { record: { id: string }; privateKey: Uint8Array },
  target: string,
): Promise<{ status: number; body: string }> {
  const response = await signedRead(served, pop, target);
  return { status: response.status, body: await response.text() };
}

// Receipt signatures must be checked against wire bytes, not a UTF-8 round trip.
export async function signedGetBytes(
  served: ServedGateway,
  pop: { record: { id: string }; privateKey: Uint8Array },
  target: string,
): Promise<{ status: number; body: Uint8Array }> {
  const response = await signedRead(served, pop, target);
  return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
}

async function signedRead(
  served: ServedGateway,
  pop: { record: { id: string }; privateKey: Uint8Array },
  target: string,
): Promise<Response> {
  const nonce = randomNonce();
  const fields: PopFields = {
    ts: Math.floor(Date.now() / 1000),
    nonce,
    method: 'GET',
    target,
    bodyDigestHex: EMPTY_BODY_SHA256_HEX,
  };
  return ask(served, target, {
    headers: {
      authorization: signPopAuthorization(fields, pop.record.id, pop.privateKey),
      'x-ashaveri-nonce': toBase64Url(nonce),
    },
  });
}
