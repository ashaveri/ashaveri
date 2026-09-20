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

export interface PopVector {
  name: string;
  note: string;
  fields: {
    ts: number;
    nonce: string;
    method: string;
    target: string;
    bodyBase64Url: string;
    bodyDigestHex: string;
  };
  signingString: string;
  authorization: string;
}

export interface PopVectorFile {
  version: 1;
  description: string;
  scheme: string;
  separator: string;
  emptyBodySha256Hex: string;
  key: { id: string; privateKeyHex: string; publicKeyHex: string };
  vectors: PopVector[];
}

export function loadPopVectors(): PopVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'pop-v1.json'), 'utf8')) as PopVectorFile;
}

/** What a digest vector states about the digest it publishes, and the bytes it is taken over. */
export interface DigestRule {
  receiptField: string;
  algorithm: string;
  input: string;
  encoding: string;
  computedBefore: string;
}

export interface RequestVector {
  name: string;
  note: string;
  bodyBase64Url: string;
  bodyByteLength: number;
  reqHex: string;
}

export interface RequestVectorFile {
  version: number;
  description: string;
  rule: DigestRule;
  vectors: RequestVector[];
}

/** The request-body digests a receipt claims in `req`. */
export function loadReqVectors(): RequestVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'req-v1.json'), 'utf8')) as RequestVectorFile;
}

export interface ResponseVector {
  name: string;
  note: string;
  contentType: string;
  /** The name of the entry in `req-v1.json` carrying the request these bytes answered. */
  request: string;
  requestBase64Url: string;
  /** The response as it was written, piece by piece, which for a stream is not one piece. */
  chunksBase64Url: string[];
  responseBase64Url: string;
  responseByteLength: number;
  resHex: string;
}

export interface ResponseVectorFile {
  version: number;
  description: string;
  rule: DigestRule;
  framing: {
    contentType: string;
    fieldPrefix: string;
    frameSeparator: string;
    terminator: string;
    note: string;
  };
  vectors: ResponseVector[];
}

/** The response-body digests a receipt claims in `res`, framed bytes included. */
export function loadResVectors(): ResponseVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'res-v1.json'), 'utf8')) as ResponseVectorFile;
}

/** What one retirement recorded, in the two places the record layout keeps it. */
export interface ChainTrimPayload {
  seamHex: string;
  byAge: number;
  byCount: number;
  maxAgeSeconds: number;
  maxCount: number;
}

/** One record of a store file, field by field, with its own bytes beside it. */
export interface ChainRecord {
  /** Where the frame starts in the file image, in bytes from the file's first byte. */
  offset: number;
  kind: number;
  length: number;
  frameByteLength: number;
  prevHex: string;
  iat: number;
  id: string;
  payloadBase64Url: string;
  digestHex: string;
  frameBase64Url: string;
  trim?: ChainTrimPayload;
}

export interface ChainPut {
  id: string;
  iat: number;
  payloadBase64Url: string;
}

export interface ChainTrimEvent {
  at: number;
  byAge: number;
  byCount: number;
  under: { maxAgeSeconds?: number; maxCount?: number };
}

/** What a reader reports about a store file, beside the bytes the file holds. */
export interface ChainStateVector {
  anchorHex: string;
  retired: { byAge: number; byCount: number; trims: ChainTrimEvent[] };
}

export interface ChainScenario {
  name: string;
  note: string;
  retention?: { maxAgeSeconds?: number; maxCount?: number };
  clockSeconds: number;
  puts: ChainPut[];
  fileBase64Url: string;
  fileByteLength: number;
  records: ChainRecord[];
  headHex: string;
  window: { from: number; to: number; count: number };
  served: Record<string, string>;
  chainState: ChainStateVector;
}

/** A file image no store wrote, and the refusal the reader answers it with. */
export interface ChainRefusal {
  name: string;
  note: string;
  tamper: Record<string, unknown>;
  imageBase64Url: string;
  imageByteLength: number;
  code: string;
  message: string;
}

/** Two records with an interrupted append at the tail, and what a reader makes of them. */
export interface ChainTail {
  name: string;
  note: string;
  /** The scenario whose image was cut, and how many bytes came off its end. */
  of: string;
  cutBytes: number;
  imageBase64Url: string;
  headHex: string;
  repairedImageBase64Url: string;
  served: Record<string, string>;
  unserved: string[];
  next: ChainPut;
  imageAfterNextBase64Url: string;
  recordsAfterNext: ChainRecord[];
}

export interface ChainVectorFile {
  version: number;
  description: string;
  layout: {
    file: string;
    record: string;
    lengthCovers: string;
    digestInput: string;
    digest: string;
    integers: string;
    kinds: { receipt: number; trim: number };
    receiptPayload: string;
    trimPayload: string;
    notes: string[];
  };
  scenarios: ChainScenario[];
  tails: ChainTail[];
  refusals: ChainRefusal[];
}

/** The receipt store record format, as file images and the state a reader derives from them. */
export function loadChainVectors(): ChainVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'chain-v1.json'), 'utf8')) as ChainVectorFile;
}
