import { AttestationError } from './errors.js';

const MAX_ATTESTATION_BYTES = 10 * 1024 * 1024;

export class MsgpackReader {
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

  peekByte(context: string): number {
    this.require(1, context);
    return this.bytes[this.pos] as number;
  }

  readMapHeader(context: string): number {
    const marker = this.readByte(context);
    if ((marker & 0xf0) === 0x80) return marker & 0x0f;
    if (marker === 0xde) return this.readSize(2, context);
    if (marker === 0xdf) return this.readSize(4, context);
    throw new AttestationError('MALFORMED_ATTESTATION', `${context} is not a msgpack map`);
  }

  readArrayHeader(context: string): number {
    const marker = this.readByte(context);
    if ((marker & 0xf0) === 0x90) return marker & 0x0f;
    if (marker === 0xdc) return this.readSize(2, context);
    if (marker === 0xdd) return this.readSize(4, context);
    throw new AttestationError('MALFORMED_ATTESTATION', `${context} is not a msgpack array`);
  }

  readUint(context: string): number {
    const marker = this.readByte(context);
    if (marker <= 0x7f) return marker;
    if (marker === 0xcc) return this.readByte(context);
    if (marker === 0xcd) return this.readSize(2, context);
    if (marker === 0xce) return this.readSize(4, context);
    if (marker === 0xcf) {
      const hi = this.readSize(4, context);
      const lo = this.readSize(4, context);
      if (hi > 0x1fffff) {
        throw new AttestationError('MALFORMED_ATTESTATION', `${context} exceeds 53-bit integer range`);
      }
      return hi * 0x100000000 + lo;
    }
    throw new AttestationError('MALFORMED_ATTESTATION', `${context} is not an unsigned integer`);
  }

  readBin(context: string): Uint8Array {
    const marker = this.readByte(context);
    let len: number;
    if (marker === 0xc4) len = this.readByte(context);
    else if (marker === 0xc5) len = this.readSize(2, context);
    else if (marker === 0xc6) len = this.readSize(4, context);
    else throw new AttestationError('MALFORMED_ATTESTATION', `${context} is not msgpack bin data`);
    this.require(len, context);
    const out = this.bytes.slice(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  readStr(context: string): string {
    const marker = this.readByte(context);
    let len: number;
    if ((marker & 0xe0) === 0xa0) len = marker & 0x1f;
    else if (marker === 0xd9) len = this.readByte(context);
    else if (marker === 0xda) len = this.readSize(2, context);
    else if (marker === 0xdb) len = this.readSize(4, context);
    else throw new AttestationError('MALFORMED_ATTESTATION', `${context} is not a msgpack string`);
    this.require(len, context);
    const bytes = this.bytes.slice(this.pos, this.pos + len);
    this.pos += len;
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }

  readNil(context: string): null {
    const marker = this.readByte(context);
    if (marker !== 0xc0) {
      throw new AttestationError('MALFORMED_ATTESTATION', `${context} is not nil`);
    }
    return null;
  }

  readValue(context: string): unknown {
    const marker = this.readByte(context);
    if (marker <= 0x7f) return marker;
    if (marker >= 0xe0) return marker - 0x100;
    if (marker === 0xc0) return null;
    if (marker === 0xc2) return false;
    if (marker === 0xc3) return true;
    if ((marker & 0xf0) === 0x80 || marker === 0xde || marker === 0xdf) {
      const count = marker === 0xde ? this.readSize(2, context) : marker === 0xdf ? this.readSize(4, context) : marker & 0x0f;
      const out: Record<string, unknown> = {};
      for (let i = 0; i < count; i++) {
        const key = this.readStr(`${context} key ${i}`);
        out[key] = this.readValue(`${context}.${key}`);
      }
      return out;
    }
    if ((marker & 0xf0) === 0x90 || marker === 0xdc || marker === 0xdd) {
      const count = marker === 0xdc ? this.readSize(2, context) : marker === 0xdd ? this.readSize(4, context) : marker & 0x0f;
      const out: unknown[] = [];
      for (let i = 0; i < count; i++) {
        out.push(this.readValue(`${context}[${i}]`));
      }
      return out;
    }
    if ((marker & 0xe0) === 0xa0 || marker === 0xd9 || marker === 0xda || marker === 0xdb) {
      const len =
        (marker & 0xe0) === 0xa0
          ? marker & 0x1f
          : marker === 0xd9
            ? this.readByte(context)
            : marker === 0xda
              ? this.readSize(2, context)
              : this.readSize(4, context);
      this.require(len, context);
      const bytes = this.bytes.slice(this.pos, this.pos + len);
      this.pos += len;
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }
    if (marker === 0xc4 || marker === 0xc5 || marker === 0xc6) {
      const len = marker === 0xc4 ? this.readByte(context) : marker === 0xc5 ? this.readSize(2, context) : this.readSize(4, context);
      this.require(len, context);
      const out = this.bytes.slice(this.pos, this.pos + len);
      this.pos += len;
      return out;
    }
    if (marker === 0xca) {
      this.require(4, context);
      const view = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.pos, 4);
      this.pos += 4;
      return view.getFloat32(0, false);
    }
    if (marker === 0xcb) {
      this.require(8, context);
      const view = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.pos, 8);
      this.pos += 8;
      return view.getFloat64(0, false);
    }
    if (marker === 0xcc) return this.readByte(context);
    if (marker === 0xcd) return this.readSize(2, context);
    if (marker === 0xce) return this.readSize(4, context);
    if (marker === 0xcf) {
      const hi = this.readSize(4, context);
      const lo = this.readSize(4, context);
      if (hi > 0x1fffff) {
        throw new AttestationError('MALFORMED_ATTESTATION', `${context} exceeds 53-bit integer range`);
      }
      return hi * 0x100000000 + lo;
    }
    if (marker === 0xd0) return this.readByte(context) - 0x100;
    if (marker === 0xd1) return this.readSize(2, context) - 0x10000;
    if (marker === 0xd2) return this.readSize(4, context) - 0x100000000;
    if (marker === 0xd3) {
      this.require(8, context);
      const view = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.pos, 8);
      this.pos += 8;
      return view.getBigInt64(0, false);
    }
    if (marker >= 0xd4 && marker <= 0xd8) {
      const size = marker - 0xd4;
      this.require(size, context);
      const out = this.bytes.slice(this.pos, this.pos + size);
      this.pos += size;
      return out;
    }
    if (marker === 0xc7 || marker === 0xc8 || marker === 0xc9) {
      const len = marker === 0xc7 ? this.readByte(context) : marker === 0xc8 ? this.readSize(2, context) : this.readSize(4, context);
      this.readByte(context);
      this.require(len, context);
      const out = this.bytes.slice(this.pos, this.pos + len);
      this.pos += len;
      return out;
    }
    throw new AttestationError('MALFORMED_ATTESTATION', `${context} uses unsupported msgpack marker 0x${marker.toString(16)}`);
  }

  skipValue(context: string): void {
    this.readValue(context);
  }

  private readByte(context: string): number {
    this.require(1, context);
    return this.bytes[this.pos++] as number;
  }

  private readSize(len: number, context: string): number {
    this.require(len, context);
    let v = 0;
    for (let i = 0; i < len; i++) {
      v = v * 0x100 + (this.bytes[this.pos + i] as number);
    }
    this.pos += len;
    return v;
  }

  private require(len: number, context: string): void {
    if (this.remaining < len) {
      throw new AttestationError('MALFORMED_ATTESTATION', `unexpected end of input in ${context}`);
    }
  }
}

export function isMsgpackMapPrefix(firstByte: number): boolean {
  return (firstByte & 0xf0) === 0x80 || firstByte === 0xde || firstByte === 0xdf;
}
