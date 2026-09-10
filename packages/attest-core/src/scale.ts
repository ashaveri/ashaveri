import { AttestationError } from './errors.js';

const MAX_ATTESTATION_BYTES = 10 * 1024 * 1024;

export class ScaleReader {
  private pos = 0;

  constructor(private readonly bytes: Uint8Array) {
    if (bytes.length > MAX_ATTESTATION_BYTES) {
      throw new AttestationError('MALFORMED_ATTESTATION', `attestation exceeds ${MAX_ATTESTATION_BYTES} bytes`);
    }
  }

  get remaining(): number {
    return this.bytes.length - this.pos;
  }

  assertEnd(context: string): void {
    if (this.remaining !== 0) {
      throw new AttestationError('TRAILING_BYTES', `${this.remaining} bytes after ${context}`);
    }
  }

  readByte(context: string): number {
    this.require(1, context);
    return this.bytes[this.pos++] as number;
  }

  readU32(context: string): number {
    this.require(4, context);
    const v =
      (this.bytes[this.pos] as number) |
      ((this.bytes[this.pos + 1] as number) << 8) |
      ((this.bytes[this.pos + 2] as number) << 16) |
      ((this.bytes[this.pos + 3] as number) << 24);
    this.pos += 4;
    return v >>> 0;
  }

  readCompact(context: string): number {
    this.require(1, context);
    const first = this.bytes[this.pos] as number;
    const mode = first & 0x03;
    if (mode === 0) {
      this.pos += 1;
      return first >> 2;
    }
    if (mode === 1) {
      this.require(2, context);
      const v = (this.bytes[this.pos] as number) | ((this.bytes[this.pos + 1] as number) << 8);
      this.pos += 2;
      return v >>> 2;
    }
    if (mode === 2) {
      this.require(4, context);
      const v =
        (this.bytes[this.pos] as number) |
        ((this.bytes[this.pos + 1] as number) << 8) |
        ((this.bytes[this.pos + 2] as number) << 16) |
        ((this.bytes[this.pos + 3] as number) * 0x1000000);
      this.pos += 4;
      if (v > MAX_ATTESTATION_BYTES) {
        throw new AttestationError('MALFORMED_ATTESTATION', `${context} length ${v} exceeds size limit`);
      }
      return v;
    }
    throw new AttestationError('MALFORMED_ATTESTATION', `${context} uses big-integer compact encoding`);
  }

  readFixed(len: number, context: string): Uint8Array {
    this.require(len, context);
    const out = this.bytes.slice(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  readVec(context: string): Uint8Array {
    const len = this.readCompact(context);
    return this.readFixed(len, context);
  }

  readString(context: string): string {
    const bytes = this.readVec(context);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return text;
  }

  readVecItems<T>(readItem: (context: string) => T, context: string): T[] {
    const count = this.readCompact(context);
    const items: T[] = [];
    for (let i = 0; i < count; i++) {
      items.push(readItem(`${context}[${i}]`));
    }
    return items;
  }

  private require(len: number, context: string): void {
    if (this.remaining < len) {
      throw new AttestationError('MALFORMED_ATTESTATION', `unexpected end of input in ${context}`);
    }
  }
}
