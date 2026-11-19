import { afterEach, describe, expect, it, vi } from 'vitest';
import fs, { type FileHandle } from 'node:fs/promises';
import { dirname } from 'node:path';
import { AsyncMarkedStreamTail, StreamCompletionGate } from '../src/stream-completion.js';
import { MarkedStreamTail, markingFrame } from '../src/marking.js';

const TERMINAL = Buffer.from('data: [DONE]\r\n\r\n');
const COMMENTS = Buffer.from(`: ${'confidential-answer-'.repeat(50)}\n\n`.repeat(1024));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((yes) => { resolve = yes; });
  return { promise, resolve };
}

function storage() {
  const paths: string[] = [];
  const handles: FileHandle[] = [];
  const open = fs.open.bind(fs);
  vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
    const file = await open(...args);
    paths.push(String(args[0]));
    handles.push(file);
    return file;
  });
  return { paths, handles };
}

function residentBytes(value: unknown, seen = new Set<unknown>()): number {
  if (value === null || typeof value !== 'object' || seen.has(value)) return 0;
  seen.add(value);
  if (ArrayBuffer.isView(value)) {
    if (seen.has(value.buffer)) return 0;
    seen.add(value.buffer);
    return value.buffer.byteLength;
  }
  if (value instanceof Promise) return 0;
  return Object.values(value).reduce<number>((sum, item: unknown) => sum + residentBytes(item, seen), 0);
}

async function removed(paths: string[]) {
  for (const path of paths) await expect(fs.stat(dirname(path))).rejects.toMatchObject({ code: 'ENOENT' });
}

afterEach(() => { vi.restoreAllMocks(); });

const MARK = markingFrame('mock-model-1', 1).frame;

function syncMarked(chunks: Uint8Array[]): Buffer {
  const tail = new MarkedStreamTail();
  const out = chunks.map((chunk) => Buffer.from(tail.writable(chunk)));
  return Buffer.concat([...out, ...tail.finishing(MARK)]);
}

describe('bounded asynchronous marking tail', () => {
  it('matches the synchronous oracle for every cut of bounded terminal and frame fixtures', async () => {
    const bodies = [
      '', 'data: [DONE]', 'data:[DONE]', 'data: [DONE]\r\n\n\r',
      'data: {"a":1}data: [DONE]\n\n', 'data: {"a":1}\r\ndata:[DONE]\r\n',
      'data: [DONE]\r\n\r\ndata: {"after":true}\n\n',
      'data: [DONE]\n\ndata:[DONE]\r\n', 'data: [DONE]\n\ndata: [DO',
      'data: {"a":1}', 'data: {"a":1}\r', 'data: {"a":1}\r\n',
      'data: {"a":1}\n\r', 'data: [DO', 'data:[DO',
    ];
    for (const body of bodies) {
      const bytes = Buffer.from(body);
      const splits = Array.from({ length: bytes.length + 1 }, (_, at) => [bytes.subarray(0, at), bytes.subarray(at)]);
      splits.push(Array.from(bytes, (byte) => Buffer.of(byte)));
      for (const chunks of splits) {
        const tail = new AsyncMarkedStreamTail();
        const output: Buffer[] = [];
        const send = async (part: Uint8Array) => { output.push(Buffer.from(part)); };
        try {
          for (const chunk of chunks) await tail.write(chunk, send);
          await tail.finishing(MARK, send);
          expect(Buffer.concat(output), JSON.stringify(chunks.map((part) => part.toString()))).toEqual(syncMarked(chunks));
        } finally {
          await tail.dispose();
        }
      }
    }
  });

  it.each(['\n', '\r\n', '\r\n\n\r'])('bounds retained buffers and copies for %j suffixes', async (ending) => {
    const io = storage();
    const tail = new AsyncMarkedStreamTail();
    const output: Buffer[] = [];
    const send = async (part: Uint8Array) => { output.push(Buffer.from(part)); };
    const block = Buffer.from(ending.repeat(4096));
    const head = Buffer.from(`data: {"large":"${'a'.repeat(128 * 1024)}"}\n\n`);
    const huge = Buffer.concat([head, TERMINAL, Buffer.from(ending.repeat(65536))]);
    try {
      const copying = vi.spyOn(Buffer, 'from');
      const joining = vi.spyOn(Buffer, 'concat');
      await tail.write(huge, send);
      const copies = copying.mock.calls.map(([bytes]) => ArrayBuffer.isView(bytes) ? bytes.byteLength : 0);
      const joins = joining.mock.calls.map(([parts]) => parts.reduce((sum, part) => sum + part.byteLength, 0));
      copying.mockRestore();
      joining.mockRestore();
      expect(Math.max(...copies, ...joins)).toBeLessThanOrEqual(64 * 1024);
      expect(Buffer.concat(output)).toEqual(head);
      expect(residentBytes(tail)).toBeLessThan(128 * 1024);
      for (let i = 0; i < 32; i++) {
        await tail.write(block, send);
        expect(residentBytes(tail)).toBeLessThan(128 * 1024);
      }
      expect(io.paths).toHaveLength(1);
      const disk = await fs.readFile(io.paths[0]!);
      expect(disk.includes(TERMINAL)).toBe(false);
      expect(disk.includes(block)).toBe(false);
      await tail.finishing(MARK, send);
      expect(Math.max(...output.map((part) => part.length))).toBeLessThanOrEqual(64 * 1024);
      expect(Buffer.concat(output)).toEqual(Buffer.concat([head, MARK, huge.subarray(head.length), ...Array.from({ length: 32 }, () => block)]));
    } finally {
      await tail.dispose();
    }
    await removed(io.paths);
    expect(residentBytes(tail)).toBeLessThan(16 * 1024);
    for (const handle of io.handles) await expect(handle.stat()).rejects.toMatchObject({ code: 'EBADF' });
  });

  it.each([false, true])('replays a displaced sentinel before later content (final sentinel=%s)', async (finalSentinel) => {
    const io = storage();
    const tail = new AsyncMarkedStreamTail();
    const old = Buffer.concat([TERMINAL, Buffer.from('\r\n\n\r'.repeat(32768))]);
    const after = Buffer.from('data: {"after":true}\n\n');
    const output: Buffer[] = [];
    const entered = deferred();
    const release = deferred();
    let pending = false;
    let readDuringSend = false;
    await tail.write(old, async () => undefined);
    const file = io.handles[0]!;
    const read = file.read.bind(file);
    vi.spyOn(file, 'read').mockImplementation(async (...args: Parameters<typeof file.read>) => {
      if (pending) readDuringSend = true;
      return read(...args);
    });
    const send = async (bytes: Uint8Array) => {
      output.push(Buffer.from(bytes));
      if (output.length === 1) {
        pending = true;
        entered.resolve();
        await release.promise;
        pending = false;
      }
    };
    const replay = tail.write(Buffer.concat([after, ...(finalSentinel ? [TERMINAL] : [])]), send);
    try {
      await entered.promise;
      expect(output).toHaveLength(1);
      expect(readDuringSend).toBe(false);
      release.resolve();
      await replay;
      expect(readDuringSend).toBe(false);
      await removed(io.paths);
      await tail.finishing(MARK, send);
      expect(Buffer.concat(output)).toEqual(Buffer.concat([old, after, MARK, ...(finalSentinel ? [TERMINAL] : [])]));
    } finally {
      release.resolve();
      await replay;
      await tail.dispose();
    }
  });

  it('joins a pending marking spill on abort and refuses further input', async () => {
    const io = storage();
    const tail = new AsyncMarkedStreamTail();
    const suffix = Buffer.from('\r\n'.repeat(65536));
    await tail.write(Buffer.concat([TERMINAL, suffix]), async () => undefined);
    const entered = deferred();
    const release = deferred();
    const file = io.handles[0]!;
    const write = file.write.bind(file);
    vi.spyOn(file, 'write').mockImplementationOnce(async (...args: Parameters<typeof file.write>) => {
      entered.resolve();
      await release.promise;
      return write(...args);
    });
    const pending = tail.write(suffix, async () => undefined).catch((error: unknown) => error);
    await entered.promise;
    const cleanup = tail.dispose();
    try {
      await expect(tail.write(suffix, async () => undefined)).rejects.toThrow();
      release.resolve();
      expect(await pending).toBeInstanceOf(Error);
      await cleanup;
      await removed(io.paths);
    } finally {
      release.resolve();
      await pending;
      await cleanup;
    }
  });

  it.each(['write', 'read', 'send', 'authenticate'] as const)('cleans marking storage after %s failure', async (failure) => {
    const io = storage();
    const tail = new AsyncMarkedStreamTail();
    const suffix = Buffer.from('\r\n'.repeat(65536));
    await tail.write(Buffer.concat([TERMINAL, suffix]), async () => undefined);
    const file = io.handles[0]!;
    if (failure === 'write') vi.spyOn(file, 'write').mockRejectedValueOnce(new Error('storage write failed'));
    if (failure === 'read') vi.spyOn(file, 'read').mockRejectedValueOnce(new Error('storage read failed'));
    if (failure === 'authenticate') {
      const bytes = await fs.readFile(io.paths[0]!);
      bytes[20] = bytes[20]! ^ 1;
      await fs.writeFile(io.paths[0]!, bytes);
    }
    const output: Buffer[] = [];
    const send = async (bytes: Uint8Array) => {
      if (failure === 'send') throw new Error('sink failed');
      output.push(Buffer.from(bytes));
    };
    try {
      await expect(tail.write(failure === 'write' ? suffix : Buffer.from('data: {"after":true}\n\n'), send)).rejects.toThrow();
      expect(output).toEqual([]);
      await removed(io.paths);
    } finally {
      await tail.dispose();
    }
  });
});

describe('bounded process-local encrypted completion spool', () => {
  it('retains only bounded storage for one huge chunk and repeated complete comments', async () => {
    const io = storage();
    const gate = new StreamCompletionGate();
    const output: Buffer[] = [];
    const send = async (bytes: Uint8Array) => { output.push(Buffer.from(bytes)); };
    try {
      await gate.write(Buffer.from('data: {"early":true}\n\n'), send);
      expect(Buffer.concat(output).toString()).toBe('data: {"early":true}\n\n');
      output.length = 0;
      const huge = Buffer.concat([TERMINAL, COMMENTS]);
      const copying = vi.spyOn(Buffer, 'from');
      await gate.write(huge, send);
      const copies = copying.mock.calls.map(([bytes]) => ArrayBuffer.isView(bytes) ? bytes.byteLength : 0);
      copying.mockRestore();
      expect(Math.max(...copies)).toBeLessThanOrEqual(64 * 1024);
      expect(residentBytes(gate)).toBeLessThan(128 * 1024);
      for (let i = 0; i < 64; i++) await gate.write(COMMENTS.subarray(0, 4096), send);
      expect(residentBytes(gate)).toBeLessThan(128 * 1024);
      expect(output).toEqual([]);
      expect(io.paths).toHaveLength(1);
      const disk = await fs.readFile(io.paths[0]!);
      expect(disk.length).toBeGreaterThan(512 * 1024);
      expect(disk.includes(Buffer.from('confidential-answer-'))).toBe(false);
      expect(disk.includes(TERMINAL)).toBe(false);
      if (process.platform !== 'win32') {
        expect((await fs.stat(io.paths[0]!)).mode & 0o777).toBe(0o600);
        expect((await fs.stat(dirname(io.paths[0]!))).mode & 0o777).toBe(0o700);
      }
      await gate.finishing(send);
      expect(Math.max(...output.map((part) => part.length))).toBeLessThanOrEqual(64 * 1024);
      expect(Buffer.concat(output)).toEqual(Buffer.concat([TERMINAL, COMMENTS, ...Array.from({ length: 64 }, () => COMMENTS.subarray(0, 4096))]));
    } finally {
      await gate.dispose();
    }
    await removed(io.paths);
    for (const handle of io.handles) await expect(handle.stat()).rejects.toMatchObject({ code: 'EBADF' });
    expect(residentBytes(gate)).toBeLessThan(16 * 1024);
  });

  it('keeps a threshold-sized suffix in memory and spills the next byte', async () => {
    const io = storage();
    const gate = new StreamCompletionGate();
    const suffix = Buffer.concat([TERMINAL, Buffer.alloc(64 * 1024 - TERMINAL.length, 0x61)]);
    const output: Buffer[] = [];
    try {
      await gate.write(suffix, async () => undefined);
      expect(io.paths).toEqual([]);
      await gate.write(Buffer.of(0x62), async () => undefined);
      expect(io.paths).toHaveLength(1);
      await gate.finishing(async (bytes) => { output.push(Buffer.from(bytes)); });
      expect(Buffer.concat(output)).toEqual(Buffer.concat([suffix, Buffer.of(0x62)]));
    } finally {
      await gate.dispose();
    }
    await removed(io.paths);
  });

  it('uses independent encryption for identical concurrent spools', async () => {
    const io = storage();
    const gates = [new StreamCompletionGate(), new StreamCompletionGate()];
    try {
      for (const gate of gates) await gate.write(Buffer.concat([TERMINAL, COMMENTS]), async () => undefined);
      expect(io.paths).toHaveLength(2);
      expect(dirname(io.paths[0]!)).not.toBe(dirname(io.paths[1]!));
      expect(await fs.readFile(io.paths[0]!)).not.toEqual(await fs.readFile(io.paths[1]!));
    } finally {
      await Promise.all(gates.map((gate) => gate.dispose()));
    }
    await removed(io.paths);
  });

  it.each(['open', 'chmod'] as const)('removes its directory after %s fails', async (failure) => {
    const gate = new StreamCompletionGate();
    const paths: string[] = [];
    const make = fs.mkdtemp.bind(fs);
    vi.spyOn(fs, 'mkdtemp').mockImplementation(async (...args: Parameters<typeof fs.mkdtemp>) => {
      const directory = await make(...args);
      paths.push(String(directory));
      return directory;
    });
    vi.spyOn(fs, failure).mockRejectedValueOnce(new Error('private path'));
    await expect(gate.write(Buffer.concat([TERMINAL, COMMENTS]), async () => undefined)).rejects.toThrow();
    expect(paths).toHaveLength(1);
    for (const path of paths) await expect(fs.stat(path)).rejects.toMatchObject({ code: 'ENOENT' });
    await gate.dispose();
  });

  it('awaits socket replay before reading another record', async () => {
    const io = storage();
    const gate = new StreamCompletionGate();
    const entered = deferred();
    const release = deferred();
    await gate.write(Buffer.concat([TERMINAL, COMMENTS]), async () => undefined);
    const file = io.handles[0]!;
    const read = file.read.bind(file);
    let sinkPending = false;
    let readDuringSend = false;
    vi.spyOn(file, 'read').mockImplementation(async (...args: Parameters<typeof file.read>) => {
      if (sinkPending) readDuringSend = true;
      return read(...args);
    });
    const chunks: Buffer[] = [];
    const replay = gate.finishing(async (bytes) => {
      chunks.push(Buffer.from(bytes));
      if (chunks.length === 1) {
        sinkPending = true;
        entered.resolve();
        await release.promise;
        sinkPending = false;
      }
    });
    try {
      await entered.promise;
      expect(chunks).toHaveLength(1);
      expect(readDuringSend, 'no next record is read while the sink owns the current one').toBe(false);
      release.resolve();
      await replay;
      expect(readDuringSend).toBe(false);
      expect(Buffer.concat(chunks)).toEqual(Buffer.concat([TERMINAL, COMMENTS]));
    } finally {
      release.resolve();
      await replay;
      await gate.dispose();
    }
    await removed(io.paths);
  });

  it.each(['flip', 'truncate', 'drop-record', 'reorder', 'append'] as const)('refuses %s before exposing a terminal signal', async (damage) => {
    const io = storage();
    const gate = new StreamCompletionGate();
    const output: Uint8Array[] = [];
    await gate.write(Buffer.concat([TERMINAL, COMMENTS]), async () => undefined);
    const path = io.paths[0]!;
    const bytes = await fs.readFile(path);
    const recordSize = 4 + bytes.readUInt32BE(0) + 16;
    if (damage === 'flip') bytes[20] = bytes[20]! ^ 1;
    if (damage === 'reorder') {
      const first = Buffer.from(bytes.subarray(0, recordSize));
      bytes.copy(bytes, 0, recordSize, recordSize * 2);
      first.copy(bytes, recordSize);
    }
    await fs.writeFile(path, damage === 'truncate' ? bytes.subarray(0, bytes.length - 1)
      : damage === 'drop-record' ? bytes.subarray(0, bytes.length - recordSize)
        : damage === 'append' ? Buffer.concat([bytes, Buffer.of(0)]) : bytes);
    try {
      await expect(gate.finishing(async (part) => { output.push(part); })).rejects.toThrow();
      expect(output).toEqual([]);
      await removed(io.paths);
    } finally {
      await gate.dispose();
    }
  });

  it.each([false, true])('cleans on abort (spilled=%s) and refuses subsequent writes', async (spill) => {
    const io = storage();
    const gate = new StreamCompletionGate();
    await gate.write(TERMINAL, async () => undefined);
    if (spill) await gate.write(COMMENTS, async () => undefined);
    await gate.dispose();
    expect(io.paths.length).toBe(spill ? 1 : 0);
    await removed(io.paths);
    await expect(gate.write(COMMENTS, async () => undefined)).rejects.toThrow();
  });

  it('joins a pending write on abort without accepting more suffix bytes', async () => {
    const io = storage();
    const gate = new StreamCompletionGate();
    await gate.write(Buffer.concat([TERMINAL, COMMENTS]), async () => undefined);
    const entered = deferred();
    const release = deferred();
    const file = io.handles[0]!;
    const write = file.write.bind(file);
    vi.spyOn(file, 'write').mockImplementationOnce(async (...args: Parameters<typeof file.write>) => {
      entered.resolve();
      await release.promise;
      return write(...args);
    });
    const pending = gate.write(COMMENTS, async () => undefined).catch((error: unknown) => error);
    await entered.promise;
    const cleanup = gate.dispose();
    try {
      await expect(gate.write(COMMENTS, async () => undefined)).rejects.toThrow();
      release.resolve();
      expect(await pending).toBeInstanceOf(Error);
      await cleanup;
      await removed(io.paths);
    } finally {
      release.resolve();
      await pending;
      await cleanup;
    }
  });

  it.each(['write', 'read', 'send'] as const)('cleans after %s failure', async (failure) => {
    const io = storage();
    const gate = new StreamCompletionGate();
    await gate.write(Buffer.concat([TERMINAL, COMMENTS]), async () => undefined);
    const file = io.handles[0]!;
    if (failure === 'write') vi.spyOn(file, 'write').mockRejectedValueOnce(new Error('private path'));
    if (failure === 'read') vi.spyOn(file, 'read').mockRejectedValueOnce(new Error('private path'));
    try {
      await expect(failure === 'write' ? gate.write(COMMENTS, async () => undefined)
        : gate.finishing(async () => { if (failure === 'send') throw new Error('socket failure'); })).rejects.toThrow();
      await removed(io.paths);
    } finally {
      await gate.dispose();
    }
  });
});
