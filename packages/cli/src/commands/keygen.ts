import { randomUUID } from 'node:crypto';
import { generateSigningKey, toBase64Url, toHex } from '@ashaveri/receipt';
import { checkId } from '../records.js';
import { writeJson } from '../usage.js';

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

/**
 * The same sentence the human path ends with, because `--json` does not retire the warning: it moves
 * it. stdout has to be the object and nothing else, and a private half that leaves no notice
 * anywhere is a private half an operator assumes a file somewhere holds.
 */
const PRIVATE_HALF_NOTICE = 'The private half leaves this terminal and is not stored here.\n';

export function runKeygen(id: string | undefined, json: boolean): number {
  // Refused before a key is generated: this command prints the id on a row of its own, so one
  // carrying a newline is a forged second row in the same output as a real key.
  if (id !== undefined) checkId(id, '--id');
  const out = keygen(id);
  if (json) {
    writeJson(out);
    process.stderr.write(PRIVATE_HALF_NOTICE);
    return 0;
  }
  process.stdout.write(
    line('id:', out.id) +
      line('publicKey:', out.publicKey) +
      line('privateKeyHex:', out.privateKeyHex) +
      `Give the public key to credential add. ${PRIVATE_HALF_NOTICE}`,
  );
  return 0;
}
