import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  HOLD_RECORD_LIMITS,
  holdRecordBytes,
  type HoldRecord,
} from '@ashaveri/receipt';
import {
  newBearerCredential,
  parseAccessLine,
  renderAccessLine,
  type AccessRecord,
  type CredentialRecord,
} from '@ashaveri/signerd';
import { subjectCredential } from '../erasure-pass/part-fixture.ts';

/**
 * The identities and the readings a rights exercise is allowed to use.
 *
 * Every name here is drawn from a seeded generator, so no row of any leg can be mistaken for a person:
 * a credential id is six hex digits of a `mulberry32` draw, and the bearer secret behind it is drawn
 * randomly and never written to the record. A drill that read a real estate would state nothing about
 * the mechanism that a drill of this one states about the same code path, and it could not be run twice.
 *
 * The readings go through the shipped writer and the shipped parser of an access-log line rather than
 * through a local pair, because the arithmetic a reviewer checks is the arithmetic of the bytes a
 * gateway actually files.
 */

/** The rate a drill credential is held to: far above the traffic one run issues, so no shed is measured. */
export const DRILL_RATE = { perMinute: 1_000_000, burst: 1_000_000 };

export interface Subject {
  readonly credential: string;
  readonly record: CredentialRecord;
  /** The bearer token this subject's requests carry; held here and written nowhere. */
  readonly token: string;
}

/**
 * One synthetic data subject: a generated credential id, the record the gateway files, and a token.
 *
 * The id comes from the same generator the erasure-pass fixture uses, so the two harnesses name a
 * subject the one way, and a reviewer comparing their numbers compares the same kind of name.
 */
export function syntheticSubject(seed: number): Subject {
  const credential = subjectCredential(seed);
  const issued = newBearerCredential({ id: credential, scopes: ['read', 'complete'] });
  return {
    credential,
    record: { ...issued.record, rate: DRILL_RATE },
    token: Buffer.from(issued.secret).toString('base64url'),
  };
}

/** The line a gateway files for one request of one subject, through the shipped writer. */
export function accessLine(credential: string, at: number, ref: string): AccessRecord {
  return {
    t: at,
    rid: `drill-${ref}`,
    cred: credential,
    auth: 'bearer',
    scope: 'complete',
    m: 'POST',
    p: '/v1/chat/completions',
    rcp: null,
    nce: ref,
    st: 200,
    dur: 1,
    deny: null,
  };
}

export function renderLine(credential: string, at: number, ref: string): string {
  return renderAccessLine(accessLine(credential, at, ref));
}

/** The one record layout this exercise writes, so a hold's shape is stated once. */
function holdDocument(issuedAt: number, credentials?: readonly string[]): HoldRecord {
  const record: HoldRecord = {
    v: 1,
    prov: 'fixture',
    at: issuedAt,
    by: 'rights drill',
    window: { from: 0, to: null },
    reason: 'a synthetic matter standing under instruction for the exercise',
    released: null,
    limits: HOLD_RECORD_LIMITS,
  };
  return credentials === undefined ? record : { ...record, credentials };
}

/** A hold that covers one credential and is in force, in the bytes the shipped reader accepts. */
export function holdOver(credential: string, issuedAt: number): Uint8Array {
  return holdRecordBytes(holdDocument(issuedAt, [credential]));
}

/** A hold that names no credential, which is the record that suspends every erasure. */
export function holdOverEverything(issuedAt: number): Uint8Array {
  return holdRecordBytes(holdDocument(issuedAt));
}

/** A hold that names some other credential, which is the control every refusal needs. */
export function holdOverOther(other: string, issuedAt: number): Uint8Array {
  return holdOver(other, issuedAt);
}

export interface VolumeFacts {
  names: string[];
  observedFiles: string[];
  lines: number;
  syntaxInvalid: number;
  syntaxInvalidLines: Record<string, string[]>;
  schemaInvalid: number;
  schemaInvalidMatches: number;
  credentialMatches: number;
  byCredential: Record<string, number>;
  uniqueByCredential: Record<string, number>;
  of(credential: string): number;
}

/** Physical lines in the scrub's two filename families, not all copies or unique requests. */
export async function readVolume(dir: string, subject?: string): Promise<VolumeFacts> {
  const names = (await readdir(dir)).sort();
  const observedFiles = names.filter((name) => /^access-\d{4}-\d{2}-\d{2}-\d{3}\.jsonl$/u.test(name) || /^journal-\d+\.jsonl$/u.test(name));
  const byCredential: Record<string, number> = {};
  const ids = new Map<string, Set<string>>();
  let lines = 0;
  let syntaxInvalid = 0;
  let schemaInvalid = 0;
  let schemaInvalidMatches = 0;
  let credentialMatches = 0;
  const syntaxInvalidLines: Record<string, string[]> = {};
  for (const name of observedFiles) {
    const text = await readFile(join(dir, name), 'utf8');
    for (const line of text.split('\n')) {
      if (line.length === 0) continue;
      lines += 1;
      let value: unknown;
      try {
        value = JSON.parse(line) as unknown;
      } catch {
        syntaxInvalid += 1;
        (syntaxInvalidLines[name] ??= []).push(line);
        continue;
      }
      const matches = subject !== undefined && value !== null && typeof value === 'object' && 'cred' in value && value.cred === subject;
      if (matches) credentialMatches += 1;
      let parsed: AccessRecord;
      try {
        parsed = parseAccessLine(line);
      } catch {
        schemaInvalid += 1;
        if (matches) schemaInvalidMatches += 1;
        continue;
      }
      const who = parsed.cred ?? '<no credential named>';
      byCredential[who] = (byCredential[who] ?? 0) + 1;
      const held = ids.get(who) ?? new Set<string>();
      held.add(parsed.rid);
      ids.set(who, held);
    }
  }
  return {
    names,
    observedFiles,
    lines,
    syntaxInvalid,
    syntaxInvalidLines,
    schemaInvalid,
    schemaInvalidMatches,
    credentialMatches,
    byCredential,
    uniqueByCredential: Object.fromEntries([...ids].map(([who, held]) => [who, held.size])),
    of(credential: string): number {
      return byCredential[credential] ?? 0;
    },
  };
}

/** The digest of a file's whole bytes, or of no bytes when the name is gone. */
export async function digestOf(path: string): Promise<{ bytes: number; sha256: string; present: boolean }> {
  try {
    const bytes = await readFile(path);
    return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), present: true };
  } catch {
    return { bytes: 0, sha256: createHash('sha256').digest('hex'), present: false };
  }
}

/** Every byte of a directory under one name, so a refusal can be proved to have moved nothing. */
export async function volumeBytes(dir: string): Promise<string> {
  const names = (await readdir(dir)).sort();
  const digest = createHash('sha256');
  for (const name of names) {
    digest.update(name);
    digest.update('\u0000');
    try {
      digest.update(await readFile(join(dir, name)));
    } catch {
      digest.update('<unreadable>');
    }
    digest.update('\u0000');
  }
  return digest.digest('hex');
}
