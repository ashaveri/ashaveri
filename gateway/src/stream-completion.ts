import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import fs, { type FileHandle } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { closesFrame, sentinelStart, unsettledSuffix, SSE_FRAME_END } from './marking.js';

const BLOCK = 64 * 1024;
const SENTINELS = [Buffer.from('data: [DONE]'), Buffer.from('data:[DONE]')];
const SENTINEL_WIDTH = Math.max(...SENTINELS.map((sentinel) => sentinel.length));
const EMPTY = Buffer.alloc(0);

class EncryptedSuffix {
  private memory: Buffer = EMPTY;
  private used = 0;
  private directory: string | undefined;
  private file: FileHandle | undefined;
  private key: Buffer = EMPTY;
  private records = 0;
  private diskBytes = 0;
  private plainBytes = 0;

  async append(bytes: Uint8Array, check: () => void): Promise<void> {
    if (this.memory.length === 0) this.memory = Buffer.alloc(BLOCK);
    for (let at = 0; at < bytes.length;) {
      check();
      if (this.used === BLOCK) await this.spill();
      check();
      const length = Math.min(BLOCK - this.used, bytes.length - at);
      this.memory.set(bytes.subarray(at, at + length), this.used);
      this.used += length;
      at += length;
    }
  }

  private async spill(): Promise<void> {
    if (this.file === undefined) {
      this.directory = await fs.mkdtemp(join(tmpdir(), 'ashaveri-response-'));
      await fs.chmod(this.directory, 0o700);
      this.file = await fs.open(join(this.directory, 'suffix'), 'wx+', 0o600);
      this.key = randomBytes(32);
    }
    const header = Buffer.alloc(4);
    header.writeUInt32BE(this.used);
    const nonce = this.nonce(this.records);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.concat([nonce, header]));
    const encrypted = cipher.update(this.memory.subarray(0, this.used));
    cipher.final();
    for (const bytes of [header, encrypted, cipher.getAuthTag()]) {
      for (let at = 0; at < bytes.length;) {
        const { bytesWritten } = await this.file.write(bytes, at, bytes.length - at);
        if (bytesWritten === 0) throw new Error('Temporary response storage write failed');
        at += bytesWritten;
      }
    }
    this.records += 1;
    this.diskBytes += this.used + 20;
    this.plainBytes += this.used;
    this.memory.fill(0);
    this.used = 0;
  }

  private nonce(index: number): Buffer {
    if (!Number.isSafeInteger(index)) throw new Error('Temporary response record counter exhausted');
    const nonce = Buffer.alloc(12);
    // A fresh in-memory key per spool makes this counter unique within its key.
    nonce.writeBigUInt64BE(BigInt(index), 4);
    return nonce;
  }

  private async checkSize(file: FileHandle): Promise<void> {
    if ((await file.stat()).size !== this.diskBytes) throw new Error('Temporary response storage length changed');
  }

  private async readExactly(file: FileHandle, bytes: Buffer, position: number): Promise<void> {
    for (let at = 0; at < bytes.length;) {
      const { bytesRead } = await file.read(bytes, at, bytes.length - at, position + at);
      if (bytesRead === 0) throw new Error('Temporary response storage truncated');
      at += bytesRead;
    }
  }

  private async walk(file: FileHandle, check: () => void, send?: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    let position = 0;
    let total = 0;
    for (let index = 0; index < this.records; index += 1) {
      check();
      const header = Buffer.alloc(4);
      await this.readExactly(file, header, position);
      const length = header.readUInt32BE();
      if (length === 0 || length > BLOCK) throw new Error('Temporary response record length invalid');
      const encrypted = Buffer.alloc(length + 16);
      await this.readExactly(file, encrypted, position + 4);
      const nonce = this.nonce(index);
      const decipher = createDecipheriv('aes-256-gcm', this.key, nonce);
      // Authenticate position and length so intact records cannot be reordered.
      decipher.setAAD(Buffer.concat([nonce, header]));
      decipher.setAuthTag(encrypted.subarray(length));
      const plain = decipher.update(encrypted.subarray(0, length));
      try {
        decipher.final();
      } catch (error) {
        plain.fill(0);
        throw error;
      }
      check();
      if (send !== undefined) await send(plain);
      position += length + 20;
      total += length;
    }
    if (position !== this.diskBytes || total !== this.plainBytes) throw new Error('Temporary response storage totals changed');
  }

  async replay(send: (bytes: Uint8Array) => Promise<void>, check: () => void): Promise<void> {
    check();
    if (this.file === undefined) {
      if (this.used > 0) await send(Buffer.from(this.memory.subarray(0, this.used)));
      return;
    }
    await this.checkSize(this.file);
    if (this.used > 0) await this.spill();
    await this.checkSize(this.file);
    // Validate the whole spool before exposing its first terminal byte.
    await this.walk(this.file, check);
    await this.walk(this.file, check, send);
  }

  async dispose(): Promise<void> {
    this.key.fill(0);
    this.key = EMPTY;
    this.memory.fill(0);
    this.memory = EMPTY;
    this.used = 0;
    try {
      await this.file?.close();
    } finally {
      this.file = undefined;
      if (this.directory !== undefined) await fs.rm(this.directory, { recursive: true, force: true });
    }
  }
}

// Copy only the scanner window, even when the caller supplies one large chunk.
function joinedWindow(prefix: Uint8Array, chunk: Uint8Array, end: number, width: number): Buffer {
  const start = Math.max(0, end - width);
  const window = Buffer.alloc(end - start);
  const before = prefix.subarray(start, Math.min(end, prefix.length));
  window.set(before);
  window.set(chunk.subarray(Math.max(0, start - prefix.length), Math.max(0, end - prefix.length)), before.length);
  return window;
}

export class AsyncMarkedStreamTail {
  private prefix: Buffer = EMPTY;
  private written: Buffer = EMPTY;
  private terminal = false;
  private suffix = new EncryptedSuffix();
  private closed = false;
  private active: Promise<void> | undefined;
  private cleanup: Promise<void> | undefined;

  private check = (): void => {
    if (this.closed) throw new Error('Response marking closed');
  };

  private async run(work: () => Promise<void>): Promise<void> {
    this.check();
    const active = Promise.resolve().then(work);
    this.active = active;
    try {
      await active;
    } catch {
      await this.dispose().catch(() => undefined);
      throw new Error('Response marking failed');
    } finally {
      if (this.active === active) this.active = undefined;
    }
  }

  private async send(bytes: Uint8Array, write: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    for (let at = 0; at < bytes.length; at += BLOCK) {
      this.check();
      const part = bytes.subarray(at, at + BLOCK);
      await write(part);
      this.written = joinedWindow(this.written, part, this.written.length + part.length, 3);
    }
  }

  async write(chunk: Uint8Array, write: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    await this.run(async () => {
      const prefix = this.prefix;
      const length = prefix.length + chunk.length;
      let end = length;
      while (end > 0) {
        const byte = end <= prefix.length ? prefix[end - 1] : chunk[end - prefix.length - 1];
        if (byte !== 0x0a && byte !== 0x0d) break;
        end -= 1;
      }
      if (this.terminal) {
        if (end === 0) {
          await this.suffix.append(chunk, this.check);
          return;
        }
        // Later content makes the held sentinel ordinary body bytes.
        await this.suffix.replay((bytes) => this.send(bytes, write), this.check);
        await this.suffix.dispose();
        this.suffix = new EncryptedSuffix();
        this.terminal = false;
      }
      const window = joinedWindow(prefix, chunk, end, SENTINEL_WIDTH);
      const sentinel = sentinelStart(window);
      const finalWindow = joinedWindow(prefix, chunk, length, SENTINEL_WIDTH);
      const keep = unsettledSuffix(finalWindow);
      const ready = sentinel >= 0 ? end - window.length + sentinel : length - keep;
      this.prefix = EMPTY;
      await this.send(prefix.subarray(0, ready), write);
      await this.send(chunk.subarray(0, Math.max(0, ready - prefix.length)), write);
      if (sentinel >= 0) {
        this.terminal = true;
        await this.suffix.append(prefix.subarray(ready), this.check);
        await this.suffix.append(chunk.subarray(Math.max(0, ready - prefix.length)), this.check);
      } else {
        this.prefix = keep === 0 ? EMPTY : finalWindow.subarray(finalWindow.length - keep);
      }
    });
  }

  async finishing(frame: Uint8Array, write: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    await this.run(async () => {
      await this.send(this.prefix, write);
      this.prefix = EMPTY;
      if (!closesFrame(this.written)) await this.send(Buffer.from(SSE_FRAME_END), write);
      await this.send(frame, write);
      await this.suffix.replay((bytes) => this.send(bytes, write), this.check);
    });
  }

  dispose(): Promise<void> {
    this.closed = true;
    this.cleanup ??= (async () => {
      await this.active?.catch(() => undefined);
      this.prefix.fill(0);
      this.prefix = EMPTY;
      this.written.fill(0);
      this.written = EMPTY;
      await this.suffix.dispose();
    })();
    return this.cleanup;
  }
}

export class StreamCompletionGate {
  private prefix: Buffer = EMPTY;
  private lineStart = true;
  private terminal = false;
  private readonly suffix = new EncryptedSuffix();
  private closed = false;
  private active: Promise<void> | undefined;
  private cleanup: Promise<void> | undefined;

  private check = (): void => {
    if (this.closed) throw new Error('Response completion closed');
  };

  private async run(work: () => Promise<void>): Promise<void> {
    this.check();
    const active = Promise.resolve().then(work);
    this.active = active;
    try {
      await active;
    } catch {
      await this.dispose().catch(() => undefined);
      throw new Error('Response completion failed');
    } finally {
      if (this.active === active) this.active = undefined;
    }
  }

  async write(chunk: Uint8Array, send: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    await this.run(async () => {
      for (let at = 0; at < chunk.length; at += BLOCK) {
        this.check();
        await this.part(chunk.subarray(at, at + BLOCK), send);
      }
    });
  }

  private async part(chunk: Uint8Array, send: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    if (this.terminal) {
      await this.suffix.append(chunk, this.check);
      return;
    }
    const bytes = this.prefix.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.prefix, chunk]);
    this.prefix = EMPTY;
    let start = 0;
    for (let at = 0; at < bytes.length; at += 1) {
      const byte = bytes[at];
      if (byte === 0x0a || byte === 0x0d) {
        if (this.lineStart && SENTINELS.some((sentinel) => bytes.subarray(start, at).equals(sentinel))) {
          this.terminal = true;
          if (start > 0) await send(bytes.subarray(0, start));
          await this.suffix.append(bytes.subarray(start), this.check);
          return;
        }
        this.lineStart = true;
        start = at + 1;
      } else if (this.lineStart && !SENTINELS.some((sentinel) =>
        at - start < sentinel.length && bytes.subarray(start, at + 1).equals(sentinel.subarray(0, at - start + 1)))) {
        this.lineStart = false;
      }
    }
    if (this.lineStart) {
      this.prefix = Buffer.from(bytes.subarray(start));
      if (start > 0) await send(bytes.subarray(0, start));
    } else {
      await send(bytes);
    }
  }

  async finishing(send: (bytes: Uint8Array) => Promise<void>): Promise<void> {
    await this.run(async () => {
      await this.suffix.replay(send, this.check);
      this.check();
      if (this.prefix.length > 0) await send(Buffer.from(this.prefix));
    });
  }

  dispose(): Promise<void> {
    this.closed = true;
    this.cleanup ??= (async () => {
      await this.active?.catch(() => undefined);
      this.prefix.fill(0);
      this.prefix = EMPTY;
      await this.suffix.dispose();
    })();
    return this.cleanup;
  }
}
