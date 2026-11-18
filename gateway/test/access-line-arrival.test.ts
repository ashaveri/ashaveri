import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import { openMemoryAccessLog, type AccessLog, type AccessRecord } from '../src/aclog.js';
import { CLOCK_SECONDS, fixedClock, generated, harness, type Harness } from './helpers.js';
import { markingFrame } from '../src/marking.js';
import { pickAddressablePort } from './support/served-gateway.js';
import { decodeReceipt, extractMarkedRegion, frameResponse, randomNonce, sha256Hex, signPopAuthorization, toBase64Url, toHex } from '@ashaveri/receipt';
import { openMemoryReceiptStore } from '../src/store.js';
import type { CompletionBackend } from '../src/backend.js';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { newPopCredential, serializeCredentialFile } from '../src/access.js';
import { ACCESS_PART_NAME, parseAccessLine } from '../src/aclog.js';
import { bootBudget, bootServing, complete, signedGet } from './support/served-gateway.js';

// Killing the server after an answer makes the volume the only witness to its access append.

const TARGET = '/v1/chat/completions';
const BODY = '{"model":"mock-model-1","messages":[{"role":"user","content":"ordering"}]}';
const delayedCredential = generated('delayed-log', ['complete', 'read']);

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

/** Delay the IO boundary, not the server: other HTTP requests can still finish. */
function delayedLog() {
  const entered = deferred<AccessRecord>();
  const release = deferred<void>();
  const memory = openMemoryAccessLog();
  const state = { calls: 0, settled: false };
  const log: AccessLog = {
    ...memory,
    async record(entry) {
      if (entry.p !== TARGET) return memory.record(entry);
      state.calls += 1;
      entered.resolve(entry);
      try {
        await release.promise;
        await memory.record(entry);
      } finally {
        state.settled = true;
      }
    },
  };
  return { log, entered, release, state };
}

async function listen(h: Harness): Promise<string> {
  await h.app.listen({ port: await pickAddressablePort(), host: '127.0.0.1' });
  return `http://127.0.0.1:${String((h.app.server.address() as AddressInfo).port)}`;
}

function post(h: Harness, base: string, body = BODY, admitted = true): Promise<Response> {
  return fetch(`${base}${TARGET}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(admitted ? h.signFor(delayedCredential.record.id, 'POST', TARGET, body) : {}),
    },
    body,
  });
}

/** A second round trip advances real socket work while the first append stays blocked. */
async function roundTrip(base: string): Promise<void> {
  const response = await fetch(`${base}/v1/weights/not-a-digest`);
  await response.text();
}

describe('buffered answers wait on one append attempt', () => {
  for (const admitted of [true, false]) {
    for (const racingClose of [false, true]) {
      it(`delays ${admitted ? 'success' : 'refusal'} with close notification ${String(racingClose)}`, async () => {
        const gate = delayedLog();
        const h = await harness({ credentials: [delayedCredential], accessLog: gate.log });
        const finishes: boolean[] = [];
        h.app.addHook('onRequest', async (request, reply) => {
          if (request.url !== TARGET) return;
          reply.raw.once('finish', () => { finishes.push(gate.state.settled); });
          // Trigger the competing flush without destroying the socket.
          if (racingClose) reply.raw.emit('close');
        });
        const base = await listen(h);
        const answer = post(h, base, BODY, admitted).then(async (response) => ({
          status: response.status, body: await response.text(),
        }));
        try {
          await gate.entered.promise;
          await roundTrip(base);
          expect(finishes, 'no complete HTTP answer while its append is pending').toEqual([]);
          gate.release.resolve();
          const received = await answer;
          expect(received.status).toBe(admitted ? 200 : 401);
          expect(received.body.length).toBeGreaterThan(0);
          expect(finishes).toEqual([true]);
          expect(gate.state.calls).toBe(1);
        } finally {
          gate.release.resolve();
          await answer;
          await h.app.close();
        }
      });
    }
  }

  it.each([false, true])('warns once without leaking the append error and still returns success (stream=%s)', async (stream) => {
    const gate = delayedLog();
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    const h = await harness({ credentials: [delayedCredential], accessLog: gate.log });
    const base = await listen(h);
    const answer = post(h, base, stream ? `${BODY.slice(0, -1)},"stream":true}` : BODY);
    try {
      await gate.entered.promise;
      gate.release.reject(new Error('secret-payload-token-path'));
      const response = await answer;
      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text).toContain('choices');
      if (stream) expect(text).toContain('data: [DONE]\n\n');
      expect(warning.mock.calls).toEqual([[
        'The access log refused a record; the response will continue without retry.',
        { code: 'ASHAVERI_ACCESS_LOG_WRITE_FAILED' },
      ]]);
      expect(gate.state.calls).toBe(1);
    } finally {
      gate.release.resolve();
      await h.app.close();
      warning.mockRestore();
    }
  });
});

const EARLY = 'data: {"piece":"early"}\n\n';

function streamingBackend(rest: ReturnType<typeof deferred<void>>, ending: string): CompletionBackend {
  return {
    async respond() {
      return {
        status: 200, contentType: 'text/event-stream',
        chunks: (async function* () {
          yield Buffer.from(EARLY);
          await rest.promise;
          // Deliberately split every byte, including data:, [DONE] and CRLF.
          for (const byte of Buffer.from(ending)) yield Uint8Array.of(byte);
        })(),
        usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
      };
    },
  };
}

describe('stream completion waits while early bytes still flow', () => {
  for (const marking of ['none', 'provenance-v1'] as const) {
    for (const ending of ['data: [DONE]\n\n', 'data:[DONE]\r\n\r\n', 'data: [DONE]\r', 'data: [DONE]', 'data: {"piece":"last"}', 'data: [DONE]\n\ndata: {"after":true}\n\n']) {
      it(`${marking} gates ${JSON.stringify(ending)}`, async () => {
        const gate = delayedLog();
        const rest = deferred<void>();
        const issuing = deferred<void>();
        const issueRelease = deferred<void>();
        const store = openMemoryReceiptStore();
        const h = await harness({ credentials: [delayedCredential], accessLog: gate.log,
          gateway: { marking, backend: streamingBackend(rest, ending), store: {
            ...store,
            async put(...args) {
              issuing.resolve();
              await issueRelease.promise;
              await store.put(...args);
            },
          } } });
        const base = await listen(h);
        let text = '';
        let ended = false;
        const first = deferred<void>();
        const terminalSettled: boolean[] = [];
        let completion: Promise<void> | undefined;
        try {
          const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
          expect(response.status).toBe(200);
          completion = (async () => {
            for await (const chunk of response.body!) {
              text += Buffer.from(chunk).toString('utf8');
              if (text.includes('early')) first.resolve();
              if (text.includes('[DONE]') && terminalSettled.length === 0) terminalSettled.push(gate.state.settled);
            }
            ended = true;
          })();
          await first.promise;
          expect(text).toBe(EARLY);
          expect(gate.state.calls).toBe(0);
          rest.resolve();
          await issuing.promise;
          await roundTrip(base);
          expect(text, 'no terminal signal while receipt persistence is pending').not.toContain('[DONE]');
          expect(ended).toBe(false);
          expect(gate.state.calls).toBe(0);
          issueRelease.resolve();
          await gate.entered.promise;
          await roundTrip(base);
          expect(text).not.toContain('[DONE]');
          expect(ended, 'EOF is also a completion boundary').toBe(false);
          const receiptPath = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
          const receipt = await fetch(`${base}${receiptPath}`, { headers: h.signFor(delayedCredential.record.id, 'GET', receiptPath, null) });
          expect(receipt.status, 'issuance finishes before the append begins').toBe(200);
          const payload = decodeReceipt(new Uint8Array(await receipt.arrayBuffer())).payload;
          gate.release.resolve();
          await completion;
          expect(gate.state.calls).toBe(1);
          expect(terminalSettled).toEqual(ending.includes('[DONE]') ? [true] : []);
          if (marking === 'none') expect(text).toBe(EARLY + ending);
          else expect(text).toContain('ashaveri');
          expect(toHex(payload.res)).toBe(sha256Hex(Buffer.from(text)));
          expect(payload.mk?.sch).toBe(marking);
          expect(toHex(payload.mk!.d)).toBe(sha256Hex(extractMarkedRegion(marking, Buffer.from(text))));
          const framed = frameResponse('text/event-stream', Buffer.from(text));
          expect(framed.framed).toBe(true);
          expect(payload.itm).toBeDefined();
          if (framed.framed) expect(payload.itm?.map((item) => toHex(item.d))).toEqual(framed.items.map((item) => toHex(item.d)));
        } finally {
          rest.resolve();
          issueRelease.resolve();
          gate.release.resolve();
          await completion;
          await h.app.close();
        }
      });
    }
  }
});

it('keeps socket backpressure for early data and the released completion tail', async () => {
  const gate = delayedLog();
  const rest = deferred<void>();
  const early = `data: {"text":"${'a'.repeat(256 * 1024)}"}\n\n`;
  const ending = `data: [DONE]\n\ndata: {"text":"${'b'.repeat(256 * 1024)}"}\n\n`;
  const h = await harness({ credentials: [delayedCredential], accessLog: gate.log, gateway: { backend: {
    async respond() {
      return { status: 200, contentType: 'text/event-stream',
        usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
        chunks: (async function* () {
          yield Buffer.from(early);
          await rest.promise;
          yield Buffer.from(ending);
        })(),
      };
    },
  } } });
  let drains = 0;
  h.app.addHook('onRequest', async (request, reply) => {
    if (request.url === TARGET) reply.raw.on('drain', () => { drains += 1; });
  });
  const base = await listen(h);
  let text = '';
  const first = deferred<void>();
  let read: Promise<void> | undefined;
  try {
    const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
    read = (async () => {
      for await (const chunk of response.body!) {
        text += Buffer.from(chunk).toString();
        if (text.length >= early.length) first.resolve();
      }
    })();
    await first.promise;
    expect(text).toBe(early);
    expect(drains).toBeGreaterThan(0);
    const earlyDrains = drains;
    rest.resolve();
    await gate.entered.promise;
    await roundTrip(base);
    expect(text).toBe(early);
    gate.release.resolve();
    await read;
    expect(text).toBe(early + ending);
    expect(drains).toBeGreaterThan(earlyDrains);
    expect(gate.state.calls).toBe(1);
  } finally {
    rest.resolve();
    gate.release.resolve();
    await read;
    await h.app.close();
  }
});

it.each(['none', 'provenance-v1'] as const)('spills %s terminal comments with upstream IO backpressure and exact bytes', async (marking) => {
  const gate = delayedLog();
  const rest = deferred<void>();
  const stored = deferred<void>();
  const release = deferred<void>();
  const advanced = deferred<void>();
  const ending = `data: [DONE]\r\n\r\n${`: ${'private response text '.repeat(48)}\r\n\r\n`.repeat(2048)}`;
  const directories: string[] = [];
  const open = fs.open.bind(fs);
  const opening = vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
    const file = await open(...args);
    if (String(args[0]).endsWith('suffix')) {
      directories.push(String(args[0]));
      const write = file.write.bind(file);
      vi.spyOn(file, 'write').mockImplementationOnce(async (...values: Parameters<typeof file.write>) => {
        stored.resolve();
        await release.promise;
        return write(...values);
      });
    }
    return file;
  });
  const h = await harness({ credentials: [delayedCredential], accessLog: gate.log, gateway: { marking, backend: {
    async respond() {
      return { status: 200, contentType: 'text/event-stream',
        usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
        chunks: (async function* () {
          yield Buffer.from(EARLY);
          await rest.promise;
          yield Buffer.from(ending);
          advanced.resolve();
        })(),
      };
    },
  } } });
  const base = await listen(h);
  let text = '';
  let read: Promise<void> | undefined;
  try {
    const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
    const first = deferred<void>();
    read = (async () => {
      for await (const chunk of response.body!) {
        text += Buffer.from(chunk).toString();
        if (text.includes('early')) first.resolve();
      }
    })();
    await first.promise;
    rest.resolve();
    expect(await Promise.race([stored.promise.then(() => 'storage'), advanced.promise.then(() => 'upstream')])).toBe('storage');
    let upstreamAdvanced = false;
    void advanced.promise.then(() => { upstreamAdvanced = true; });
    await roundTrip(base);
    expect(upstreamAdvanced).toBe(false);
    expect(text).toBe(EARLY);
    expect(gate.state.calls).toBe(0);
    release.resolve();
    await gate.entered.promise;
    await roundTrip(base);
    expect(text).toBe(EARLY);
    expect(directories).toHaveLength(1);
    const encrypted = await readFile(directories[0]!);
    expect(encrypted.includes(Buffer.from('private response text'))).toBe(false);
    gate.release.resolve();
    await read;
    if (marking === 'none') expect(text).toBe(EARLY + ending);
    else {
      const markAt = text.indexOf('data: {"id":"chatcmpl-ashaveri-marking"');
      expect(text.slice(0, markAt)).toBe(EARLY + ending);
      expect(text.slice(markAt)).toMatch(/^data: .*\n\n$/);
    }
    const path = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
    const receipt = await fetch(`${base}${path}`, { headers: h.signFor(delayedCredential.record.id, 'GET', path, null) });
    const payload = decodeReceipt(new Uint8Array(await receipt.arrayBuffer())).payload;
    expect(toHex(payload.res)).toBe(sha256Hex(Buffer.from(text)));
    expect(toHex(payload.mk!.d)).toBe(sha256Hex(extractMarkedRegion(marking, Buffer.from(text))));
    const framed = frameResponse('text/event-stream', Buffer.from(text));
    expect(framed.framed).toBe(true);
    if (framed.framed) expect(payload.itm?.map((item) => toHex(item.d))).toEqual(framed.items.map((item) => toHex(item.d)));
    await expect(fs.stat(directories[0]!)).rejects.toMatchObject({ code: 'ENOENT' });
  } finally {
    rest.resolve();
    release.resolve();
    gate.release.resolve();
    await read;
    await h.app.close();
    opening.mockRestore();
  }
});

describe('marked newline suffixes use bounded storage before upstream EOF', () => {
  for (const ending of ['\n', '\r\n', '\r\n\n\r']) {
    for (const { singleChunk, after } of [
      { singleChunk: false, after: '' },
      { singleChunk: true, after: '' },
      { singleChunk: false, after: 'data: {"after":true}\n\n' },
      { singleChunk: false, after: 'data: {"after":true}\n\ndata:[DONE]\r\n\r\n' },
    ]) {
      it(`spills ${JSON.stringify(ending)} (single chunk=${String(singleChunk)}, after=${JSON.stringify(after)}) before receipt and append`, async () => {
        const gate = delayedLog();
        const rest = deferred<void>();
        const stored = deferred<void>();
        const release = deferred<void>();
        const advanced = deferred<void>();
        const eof = deferred<void>();
        const issuing = deferred<void>();
        const issueRelease = deferred<void>();
        const store = openMemoryReceiptStore();
        const suffix = ending.repeat(4096);
        const terminal = 'data: [DONE]';
        const paths: string[] = [];
        const state = { advanced: false, eof: false, ended: false };
        const open = fs.open.bind(fs);
        const opening = vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
          const file = await open(...args);
          if (String(args[0]).endsWith('suffix')) {
            paths.push(String(args[0]));
            const write = file.write.bind(file);
            vi.spyOn(file, 'write').mockImplementationOnce(async (...values: Parameters<typeof file.write>) => {
              stored.resolve();
              await release.promise;
              return write(...values);
            });
          }
          return file;
        });
        const h = await harness({ credentials: [delayedCredential], accessLog: gate.log, gateway: {
          marking: 'provenance-v1', time: fixedClock(() => CLOCK_SECONDS), store: { ...store, async put(...args) {
            issuing.resolve();
            await issueRelease.promise;
            await store.put(...args);
          } }, backend: { async respond() {
            return { status: 200, contentType: 'text/event-stream',
              usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
              chunks: (async function* () {
                yield Buffer.from(EARLY);
                await rest.promise;
                if (singleChunk) yield Buffer.from(terminal + suffix.repeat(32));
                else {
                  yield Buffer.from('data: [DO');
                  yield Buffer.from('NE]');
                  for (let i = 0; i < 32; i++) yield Buffer.from(suffix);
                }
                state.advanced = true;
                advanced.resolve();
                await eof.promise;
                if (after) yield Buffer.from(after);
                state.eof = true;
              })(),
            };
          } },
        } });
        const base = await listen(h);
        const first = deferred<void>();
        const terminalSettled: boolean[] = [];
        let text = '';
        let read: Promise<void> | undefined;
        try {
          const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
          read = (async () => {
            for await (const chunk of response.body!) {
              text += Buffer.from(chunk).toString();
              if (text.includes('early')) first.resolve();
              if (text.includes('[DONE]') && terminalSettled.length === 0) terminalSettled.push(gate.state.settled);
            }
            state.ended = true;
          })();
          await first.promise;
          rest.resolve();
          expect(await Promise.race([stored.promise.then(() => 'storage'), advanced.promise.then(() => 'upstream')])).toBe('storage');
          await roundTrip(base);
          expect(state.advanced, 'producer cannot pass a pending spill').toBe(false);
          expect(state.eof).toBe(false);
          expect(text).toBe(EARLY);
          expect(gate.state.calls).toBe(0);
          release.resolve();
          await advanced.promise;
          expect(paths).toHaveLength(1);
          const encrypted = await readFile(paths[0]!);
          expect(encrypted.length).toBeGreaterThan(64 * 1024);
          expect(encrypted.includes(Buffer.from(terminal))).toBe(false);
          expect(encrypted.includes(Buffer.from(suffix))).toBe(false);
          eof.resolve();
          await issuing.promise;
          await roundTrip(base);
          expect(paths).toHaveLength(2);
          expect(text).not.toContain('[DONE]');
          expect(state.ended).toBe(false);
          expect(gate.state.calls).toBe(0);
          issueRelease.resolve();
          await gate.entered.promise;
          await roundTrip(base);
          expect(text).not.toContain('[DONE]');
          expect(state.ended).toBe(false);
          gate.release.resolve();
          await read;
          const mark = markingFrame('mock-model-1', CLOCK_SECONDS);
          const markText = Buffer.from(mark.frame).toString();
          const raw = EARLY + terminal + suffix.repeat(32) + after;
          const markAt = after === '' ? EARLY.length : after.includes('[DONE]') ? raw.lastIndexOf('data:[DONE]') : raw.length;
          expect(text).toBe(raw.slice(0, markAt) + markText + raw.slice(markAt));
          expect(terminalSettled).toEqual([true]);
          expect(gate.state.calls).toBe(1);
          const path = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
          const receipt = await fetch(`${base}${path}`, { headers: h.signFor(delayedCredential.record.id, 'GET', path, null) });
          expect(receipt.status).toBe(200);
          const payload = decodeReceipt(new Uint8Array(await receipt.arrayBuffer())).payload;
          expect(toHex(payload.res)).toBe(sha256Hex(Buffer.from(text)));
          expect(payload.mk?.sch).toBe('provenance-v1');
          expect(toHex(payload.mk!.d)).toBe(sha256Hex(extractMarkedRegion('provenance-v1', Buffer.from(text))));
          const framed = frameResponse('text/event-stream', Buffer.from(text));
          expect(framed.framed).toBe(true);
          if (framed.framed) expect(payload.itm).toEqual(framed.items.map((item) => ({ t: CLOCK_SECONDS, d: item.d })));
          await roundTrip(base);
          for (const path of paths) await expect(fs.stat(dirname(path))).rejects.toMatchObject({ code: 'ENOENT' });
        } finally {
          rest.resolve();
          release.resolve();
          eof.resolve();
          issueRelease.resolve();
          gate.release.resolve();
          await read;
          await h.app.close();
          opening.mockRestore();
        }
      });
    }
  }
});

it.each(['abort', 'upstream', 'write', 'read'] as const)('cleans spilled HTTP completion on %s without a terminal success', async (cause) => {
  const gate = delayedLog();
  const rest = deferred<void>();
  const yielded = deferred<void>();
  const finish = deferred<void>();
  const cleaned = deferred<void>();
  const ending = `data: [DONE]\n\n${`: ${'private text '.repeat(80)}\n\n`.repeat(256)}`;
  const upstream = { finalized: false };
  const chunks = (async function* () {
    try {
      yield Buffer.from(EARLY);
      await rest.promise;
      yield Buffer.from(ending);
      yielded.resolve();
      await finish.promise;
      yield Buffer.from(': after\n\n');
    } finally {
      upstream.finalized = true;
    }
  })();
  const closing = vi.spyOn(chunks, 'return');
  let path = '';
  const open = fs.open.bind(fs);
  const remove = fs.rm.bind(fs);
  const opening = vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
    const file = await open(...args);
    if (String(args[0]).endsWith('suffix')) {
      path = String(args[0]);
      if (cause === 'write') vi.spyOn(file, 'write').mockRejectedValueOnce(new Error('private storage path'));
      if (cause === 'read') vi.spyOn(file, 'read').mockRejectedValueOnce(new Error('private storage path'));
    }
    return file;
  });
  const removing = vi.spyOn(fs, 'rm').mockImplementation(async (...args) => {
    await remove(...args);
    if (path && String(args[0]) === dirname(path)) cleaned.resolve();
  });
  const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
  const h = await harness({ credentials: [delayedCredential], accessLog: gate.log, gateway: { backend: {
    async respond() {
      return { status: 200, contentType: 'text/event-stream',
        usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
        chunks,
      };
    },
  } } });
  const base = await listen(h);
  let text = '';
  let read: Promise<unknown> | undefined;
  try {
    const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
    const reader = response.body!.getReader();
    const first = deferred<void>();
    read = (async () => {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        text += Buffer.from(next.value).toString();
        first.resolve();
      }
    })().catch((error: unknown) => error);
    await first.promise;
    rest.resolve();
    if (cause !== 'write') {
      await yielded.promise;
      if (cause === 'abort') await reader.cancel();
      else if (cause === 'upstream') finish.reject(new Error('upstream failed'));
      else {
        finish.resolve();
        await gate.entered.promise;
        gate.release.resolve();
      }
    }
    const result = await read;
    if (cause !== 'abort') expect(result).toBeInstanceOf(Error);
    await cleaned.promise;
    expect(text).toBe(EARLY);
    await expect(fs.stat(dirname(path))).rejects.toMatchObject({ code: 'ENOENT' });
    if (cause === 'abort') {
      expect(upstream.finalized, 'spool cleanup cannot wait for a pending upstream next').toBe(false);
      finish.resolve();
    }
    await roundTrip(base);
    expect(upstream.finalized).toBe(true);
    expect(closing).toHaveBeenCalledTimes(cause === 'read' ? 0 : 1);
    await gate.entered.promise;
    gate.release.resolve();
    const receiptPath = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
    const receipt = await fetch(`${base}${receiptPath}`, { headers: h.signFor(delayedCredential.record.id, 'GET', receiptPath, null) });
    expect(receipt.status).toBe(cause === 'read' ? 200 : 404);
    await receipt.arrayBuffer();
    expect(gate.state.calls).toBe(1);
    expect(warning.mock.calls).toEqual([]);
  } finally {
    rest.resolve();
    finish.resolve();
    gate.release.resolve();
    await read;
    await h.app.close();
    opening.mockRestore();
    removing.mockRestore();
    warning.mockRestore();
    closing.mockRestore();
  }
});

it.each(['abort', 'upstream', 'mark-write', 'mark-read', 'completion-read', 'mark-cleanup', 'completion-cleanup', 'completion-read-cleanup'] as const)(
  'cleans both HTTP retained streams on %s', async (cause) => {
    const completionRead = cause.startsWith('completion-read');
    const gate = delayedLog();
    const rest = deferred<void>();
    const yielded = deferred<void>();
    const finish = deferred<void>();
    const cleaned = deferred<void>();
    const suffix = '\r\n\n\r'.repeat(32768);
    const paths: string[] = [];
    const removed = new Set<string>();
    const errors: string[] = [];
    const upstream = { finalized: false };
    const chunks = (async function* () {
      try {
        yield Buffer.from(EARLY);
        await rest.promise;
        yield Buffer.from('data: [DONE]' + suffix);
        yield Buffer.from('data: {"after":true}\n\ndata: [DONE]' + suffix);
        yielded.resolve();
        await finish.promise;
        if (cause === 'abort') yield Buffer.from(': resumed\n\n');
      } finally {
        upstream.finalized = true;
      }
    })();
    const closing = vi.spyOn(chunks, 'return');
    const open = fs.open.bind(fs);
    const remove = fs.rm.bind(fs);
    const opening = vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
      const file = await open(...args);
      if (String(args[0]).endsWith('suffix')) {
        paths.push(String(args[0]));
        if (paths.length === 3 && cause === 'mark-write') vi.spyOn(file, 'write').mockRejectedValueOnce(new Error('mark write failed'));
        if ((paths.length === 3 && cause === 'mark-read') || (paths.length === 2 && completionRead)) {
          vi.spyOn(file, 'read').mockRejectedValueOnce(new Error('spool read failed'));
        }
      }
      return file;
    });
    const removing = vi.spyOn(fs, 'rm').mockImplementation(async (...args) => {
      await remove(...args);
      const path = String(args[0]);
      if (paths.some((file) => dirname(file) === path)) {
        removed.add(path);
        if (removed.size === 3) cleaned.resolve();
      }
      if ((cause === 'mark-cleanup' && paths[2] && path === dirname(paths[2])) ||
          ((cause === 'completion-cleanup' || cause === 'completion-read-cleanup') && paths[1] && path === dirname(paths[1]))) {
        throw new Error('cleanup rejected after removal');
      }
    });
    const h = await harness({ credentials: [delayedCredential], accessLog: gate.log, gateway: {
      marking: 'provenance-v1', backend: { async respond() {
        return { status: 200, contentType: 'text/event-stream', chunks,
          usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }) };
      } },
    } });
    h.app.addHook('onRequest', async (request, reply) => {
      if (request.url === TARGET) reply.raw.socket!.on('error', (error) => { errors.push(error.message); });
    });
    const base = await listen(h);
    let text = '';
    let read: Promise<unknown> | undefined;
    try {
      const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
      const reader = response.body!.getReader();
      const first = await reader.read();
      text += Buffer.from(first.value!).toString();
      read = (async () => {
        for (;;) {
          const next = await reader.read();
          if (next.done) break;
          text += Buffer.from(next.value).toString();
        }
      })().catch((error: unknown) => error);
      rest.resolve();
      if (cause !== 'mark-write') {
        await yielded.promise;
        expect(paths).toHaveLength(3);
        expect(removed.size, 'only the displaced marking spool was disposed').toBe(1);
        if (cause === 'abort') await reader.cancel();
        else if (cause === 'mark-read' || completionRead) {
          finish.resolve();
          if (completionRead) {
            await gate.entered.promise;
            gate.release.resolve();
          }
        } else finish.reject(new Error('original upstream failure'));
      }
      const result = await read;
      if (cause !== 'abort') expect(result).toBeInstanceOf(Error);
      await cleaned.promise;
      expect(text).toBe(EARLY);
      for (const path of paths) await expect(fs.stat(dirname(path))).rejects.toMatchObject({ code: 'ENOENT' });
      if (cause === 'abort') {
        expect(upstream.finalized).toBe(false);
        finish.resolve();
      }
      await roundTrip(base);
      expect(upstream.finalized).toBe(true);
      expect(closing).toHaveBeenCalledTimes(cause === 'mark-read' || completionRead ? 0 : 1);
      if (completionRead) expect(errors).toEqual(['Response completion failed']);
      else if (cause === 'upstream' || cause.endsWith('cleanup')) expect(errors).toEqual(['original upstream failure']);
      await gate.entered.promise;
      gate.release.resolve();
      const path = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
      const receipt = await fetch(`${base}${path}`, { headers: h.signFor(delayedCredential.record.id, 'GET', path, null) });
      expect(receipt.status).toBe(completionRead ? 200 : 404);
      await receipt.arrayBuffer();
      expect(gate.state.calls).toBe(1);
    } finally {
      rest.resolve();
      finish.resolve();
      gate.release.resolve();
      await read;
      await h.app.close();
      opening.mockRestore();
      removing.mockRestore();
      closing.mockRestore();
    }
  },
);

it.each([false, true])('closes the backend generator after spool open failure (cleanup rejects=%s)', async (rejectCleanup) => {
  const rest = deferred<void>();
  const releaseCleanup = deferred<void>();
  const cleaned = deferred<void>();
  const cleanup = { entered: false, finished: false };
  const ending = `data: [DONE]\n\n${`: ${'private text '.repeat(80)}\n\n`.repeat(256)}`;
  const chunks = (async function* () {
    try {
      yield Buffer.from(EARLY);
      await rest.promise;
      yield Buffer.from(ending);
    } finally {
      cleanup.entered = true;
      await releaseCleanup.promise;
      cleanup.finished = true;
      if (rejectCleanup) throw new Error('backend cleanup rejected');
    }
  })();
  const closing = vi.spyOn(chunks, 'return');
  let path = '';
  const open = fs.open.bind(fs);
  const remove = fs.rm.bind(fs);
  const opening = vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
    if (String(args[0]).endsWith('suffix')) {
      path = String(args[0]);
      throw new Error('private spool open failure');
    }
    return open(...args);
  });
  const removing = vi.spyOn(fs, 'rm').mockImplementation(async (...args) => {
    await remove(...args);
    if (path && String(args[0]) === dirname(path)) cleaned.resolve();
  });
  const errors: Error[] = [];
  const h = await harness({ credentials: [delayedCredential], gateway: { backend: {
    async respond() {
      return { status: 200, contentType: 'text/event-stream', chunks,
        usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
      };
    },
  } } });
  h.app.addHook('onRequest', async (request, reply) => {
    if (request.url === TARGET) reply.raw.socket!.on('error', (error) => { errors.push(error); });
  });
  const base = await listen(h);
  let read: Promise<unknown> | undefined;
  let text = '';
  try {
    const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
    const reader = response.body!.getReader();
    const first = await reader.read();
    text += Buffer.from(first.value!).toString();
    read = (async () => {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        text += Buffer.from(next.value).toString();
      }
    })().catch((error: unknown) => error);
    rest.resolve();
    expect(await read).toBeInstanceOf(Error);
    await cleaned.promise;
    await roundTrip(base);
    expect(text).toBe(EARLY);
    await expect(fs.stat(dirname(path))).rejects.toMatchObject({ code: 'ENOENT' });
    expect(cleanup.entered, 'spool failure must run the suspended generator finally').toBe(true);
    expect(cleanup.finished, 'socket and spool cleanup cannot wait for upstream cleanup').toBe(false);
    expect(closing).toHaveBeenCalledTimes(1);
    releaseCleanup.resolve();
    await roundTrip(base);
    expect(cleanup.finished).toBe(true);
    expect(closing).toHaveBeenCalledTimes(1);
    expect(errors.map((error) => error.message)).toEqual(['Response completion failed']);
    const receiptPath = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
    const receipt = await fetch(`${base}${receiptPath}`, { headers: h.signFor(delayedCredential.record.id, 'GET', receiptPath, null) });
    expect(receipt.status).toBe(404);
    await receipt.arrayBuffer();
  } finally {
    rest.resolve();
    releaseCleanup.resolve();
    if (closing.mock.calls.length === 0) await chunks.return().catch(() => undefined);
    await read;
    await h.app.close();
    opening.mockRestore();
    removing.mockRestore();
    closing.mockRestore();
  }
});

describe('unfinished streams do not invent successful receipts', () => {
  it.each(['abort', 'upstream failure'] as const)('records one best-effort line on %s', async (cause) => {
    const gate = delayedLog();
    const rest = deferred<void>();
    const h = await harness({ credentials: [delayedCredential], accessLog: gate.log,
      gateway: { backend: streamingBackend(rest, 'data: [DONE]\n\n') } });
    const base = await listen(h);
    try {
      const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
      const reader = response.body!.getReader();
      const first = await reader.read();
      expect(Buffer.from(first.value!).toString()).toBe(EARLY);
      expect(gate.state.calls).toBe(0);
      if (cause === 'abort') {
        await reader.cancel();
      } else {
        const next = reader.read();
        rest.reject(new Error('upstream stopped before completion'));
        await expect(next).rejects.toThrow();
      }
      const record = await gate.entered.promise;
      expect(record.rcp).toBeNull();
      rest.resolve();
      await roundTrip(base);
      gate.release.resolve();
      const path = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
      const missing = await fetch(`${base}${path}`, { headers: h.signFor(delayedCredential.record.id, 'GET', path, null) });
      expect(missing.status).toBe(404);
      await missing.text();
      expect(gate.state.calls).toBe(1);
    } finally {
      rest.resolve();
      gate.release.resolve();
      await h.app.close();
    }
  });

  it('withholds an upstream sentinel if the upstream fails after yielding it', async () => {
    const gate = delayedLog();
    const rest = deferred<void>();
    const yielded = deferred<void>();
    const fail = deferred<void>();
    const h = await harness({ credentials: [delayedCredential], accessLog: gate.log, gateway: { backend: {
      async respond() {
        return { status: 200, contentType: 'text/event-stream',
          usage: Promise.resolve({ model: 'mock-model-1', promptTokens: 1, completionTokens: 1 }),
          chunks: (async function* () {
            yield Buffer.from(EARLY);
            await rest.promise;
            yield Buffer.from('data: [DONE]\n\n');
            yielded.resolve();
            await fail.promise;
            throw new Error('upstream failed after sentinel');
          })(),
        };
      },
    } } });
    const base = await listen(h);
    let text = '';
    let read: Promise<unknown> | undefined;
    try {
      const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
      read = (async () => {
        for await (const chunk of response.body!) text += Buffer.from(chunk).toString();
      })().catch((error: unknown) => error);
      rest.resolve();
      await yielded.promise;
      await roundTrip(base);
      expect(text).not.toContain('[DONE]');
      expect(gate.state.calls).toBe(0);
      fail.resolve();
      expect(await read).toBeInstanceOf(Error);
      await gate.entered.promise;
      gate.release.resolve();
      const path = `/v1/receipts/${String(response.headers.get('x-ashaveri-receipt-id'))}`;
      const missing = await fetch(`${base}${path}`, { headers: h.signFor(delayedCredential.record.id, 'GET', path, null) });
      expect(missing.status).toBe(404);
      await missing.text();
      expect(gate.state.calls).toBe(1);
    } finally {
      rest.resolve();
      fail.resolve();
      gate.release.resolve();
      await read;
      await h.app.close();
    }
  });

  it('joins an in-flight append when the real client closes at the completion boundary', async () => {
    const gate = delayedLog();
    const rest = deferred<void>();
    const h = await harness({ credentials: [delayedCredential], accessLog: gate.log,
      gateway: { backend: streamingBackend(rest, 'data: [DONE]\n\n') } });
    const closed = deferred<void>();
    h.app.addHook('onRequest', async (request, reply) => {
      if (request.url === TARGET) reply.raw.once('close', () => { closed.resolve(); });
    });
    const base = await listen(h);
    try {
      const response = await post(h, base, `${BODY.slice(0, -1)},"stream":true}`);
      const reader = response.body!.getReader();
      await reader.read();
      rest.resolve();
      await gate.entered.promise;
      await reader.cancel();
      await closed.promise;
      expect(gate.state.calls).toBe(1);
      gate.release.resolve();
      await roundTrip(base);
      expect(gate.state.calls).toBe(1);
    } finally {
      rest.resolve();
      gate.release.resolve();
      await h.app.close();
    }
  });
});

describe('mechanical enforcement at the actual response send', () => {
  it('enables thenable checking only for server.ts and refuses an omitted await', async () => {
    const eslint = new ESLint({ cwd: fileURLToPath(new URL('../../', import.meta.url)) });
    const filePath = fileURLToPath(new URL('../src/server.ts', import.meta.url));
    const rule = '@typescript-eslint/no-floating-promises';
    const config = await eslint.calculateConfigForFile(filePath);
    expect(config.rules[rule]).toEqual([2, { checkThenables: true, ignoreVoid: false, ignoreIIFE: false }]);
    const other = await eslint.calculateConfigForFile(fileURLToPath(new URL('../src/backend.ts', import.meta.url)));
    expect(other.rules[rule]).not.toEqual(config.rules[rule]);
    const original = await readFile(filePath, 'utf8');
    const site = "await buffered.header('x-ashaveri-receipt-id', receiptId).send(sent);";
    expect(original.split(site)).toHaveLength(2);
    const poison = original.replace(site, site.slice('await '.length));
    const line = original.slice(0, original.indexOf(site)).split('\n').length;
    const [clean] = await eslint.lintText(original, { filePath });
    expect(clean!.errorCount).toBe(0);
    const [refused] = await eslint.lintText(poison, { filePath });
    expect(refused!.messages.filter((message) => message.ruleId === rule).map((message) => message.line)).toEqual([line]);
  });
});

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

  it.each(['none', 'provenance-v1'] as const)('keeps the line when killed at the %s terminal signal, without waiting for EOF', async (marking) => {
    const before = (await logLines()).length;
    const served = await bootServing([
      '--receipts-dir', volumeDir, '--credentials-path', credentialsPath,
      '--access-log-path', accessDir, '--marking', marking,
    ]);
    try {
      const body = `${BODY.slice(0, -1)},"stream":true}`;
      const nonce = randomNonce();
      const response = await fetch(`http://127.0.0.1:${String(served.port)}${TARGET}`, {
        method: 'POST', body,
        headers: {
          'content-type': 'application/json', 'x-ashaveri-nonce': toBase64Url(nonce),
          authorization: signPopAuthorization({ ts: Math.floor(Date.now() / 1000), nonce,
            method: 'POST', target: TARGET, bodyDigestHex: sha256Hex(Buffer.from(body)) }, pop.record.id, pop.privateKey),
        },
      });
      expect(response.status).toBe(200);
      const reader = response.body!.getReader();
      let text = '';
      for (;;) {
        const next = await reader.read();
        expect(next.done, 'terminal must arrive before EOF is read').toBe(false);
        text += Buffer.from(next.value!).toString();
        if (text.includes('data: [DONE]\n\n')) {
          await served.kill();
          break;
        }
      }
      await reader.cancel().catch(() => undefined);
      expect((await logLines()).length).toBe(before + 1);
    } finally {
      await served.kill();
    }
  }, bootBudget(1) + 20_000);

  it('keeps the line when killed immediately after a buffered completion body', async () => {
    const before = (await logLines()).length;
    const served = await bootServing([
      '--receipts-dir', volumeDir, '--credentials-path', credentialsPath, '--access-log-path', accessDir,
    ]);
    try {
      const answer = await complete(served, pop);
      await served.kill();
      expect(answer.status).toBe(200);
      expect((await logLines()).length).toBe(before + 1);
    } finally {
      await served.kill();
    }
  }, bootBudget(1) + 20_000);

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
