export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('invalid base64url characters');
  }
  const padded = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Whole pairs or nothing: `Buffer.from(value, 'hex')` stops at the first nibble it cannot read and
// returns the bytes before it, so a 66-character secret with a corrupt tail would decode to the
// same 32-byte key as its first 64 characters.
const HEX_PAIRS = /^(?:[\da-fA-F]{2})*$/u;

export function fromHex(value: string): Uint8Array {
  if (!HEX_PAIRS.test(value)) {
    throw new Error('invalid hex: expected an even number of hex digits');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
