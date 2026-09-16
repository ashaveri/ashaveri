import { randomUUID } from 'node:crypto';
import { generateSigningKey, toBase64Url, toHex } from '@ashaveri/receipt';

/**
 * Eight characters, the same slice the gateway's own `credentialId` takes for a default id, so a
 * file written by both tools carries one naming convention and an operator can tell an id from a
 * prefix.
 */
export function shortId(): string {
  return randomUUID().slice(0, 8);
}

export interface KeygenResult {
  readonly id: string;
  readonly publicKey: string;
  readonly privateKeyHex: string;
}

/** `ashaveri keygen [--id <id>]`. Prints the private half once; nothing here writes it to disk. */
export function keygen(id: string | undefined): KeygenResult {
  const key = generateSigningKey();
  return {
    id: id ?? `pop-${shortId()}`,
    publicKey: toBase64Url(key.publicKey),
    privateKeyHex: toHex(key.privateKey),
  };
}

/**
 * Aligned so the two halves line up under each other when an operator copies one out of a terminal
 * and into a password manager, and so a wrapped paste cannot split a key across two lines.
 */
function line(name: string, value: string): string {
  return `${name.padEnd(16)}${value}\n`;
}

export function runKeygen(id: string | undefined, json: boolean): number {
  const out = keygen(id);
  if (json) {
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return 0;
  }
  process.stdout.write(
    line('id:', out.id) +
      line('publicKey:', out.publicKey) +
      line('privateKeyHex:', out.privateKeyHex) +
      'Give the public key to credential add. The private half leaves this terminal and is not stored here.\n',
  );
  return 0;
}
