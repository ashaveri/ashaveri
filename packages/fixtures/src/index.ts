import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import type { SigningKey, ReceiptJson } from '@ashaveri/receipt';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

export interface FixtureManifest {
  version: number;
  generatedBy: string;
  cddl: string;
  fixtures: Array<{ name: string; path: string; digestSha256: string; expected: string; note?: string }>;
}

export interface ReceiptFixture {
  name: string;
  bytes: Uint8Array;
  digest: Uint8Array;
  json: ReceiptJson | null;
}

export function loadManifest(): FixtureManifest {
  return JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as FixtureManifest;
}

export function loadReceiptFixture(name: string): ReceiptFixture {
  const manifest = loadManifest();
  const entry = manifest.fixtures.find((f) => f.name === name);
  if (!entry) throw new Error(`unknown fixture: ${name}`);
  const bytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
  const digest = sha256(bytes);
  const expected = Buffer.from(entry.digestSha256, 'hex');
  if (!Buffer.from(digest).equals(expected)) {
    throw new Error(`fixture ${name} does not match its manifest digest (regenerate with pnpm generate)`);
  }
  let json: ReceiptJson | null = null;
  const jsonPath = join(DATA, entry.path.replace(/\.cbor$/, '.json'));
  try {
    json = JSON.parse(readFileSync(jsonPath, 'utf8')) as ReceiptJson;
  } catch {
    json = null;
  }
  return { name, bytes, digest, json };
}

export interface FixtureKeyFile {
  description: string;
  privateKey: string;
  publicKey: string;
  kid: string;
}

export function loadFixtureKey(): SigningKey {
  const parsed = JSON.parse(readFileSync(join(DATA, 'keys', 'receipt-key-v1.json'), 'utf8')) as FixtureKeyFile;
  return {
    privateKey: new Uint8Array(Buffer.from(parsed.privateKey, 'hex')),
    publicKey: new Uint8Array(Buffer.from(parsed.publicKey, 'hex')),
    kid: new Uint8Array(Buffer.from(parsed.kid, 'hex')),
  };
}

export { DATA };
