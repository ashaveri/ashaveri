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
  /** Every file name in the directory, so a claim about what stands at a name is checkable. */
  names: string[];
  lines: number;
  unreadable: number;
  /** Of the refused bytes, how many name the credential the run was asked about, and how many name another. */
  unreadableNaming: number;
  unreadableElsewhere: number;
  /** The refused bytes themselves, capped, so a difference between two readings is attributable. */
  unreadableSamples: string[];
  byCredential: Record<string, number>;
  /** The subject's lines, counted by the shipped parser rather than by a name match. */
  of(credential: string): number;
}

/**
 * What stands on the volume, read back through the parser the gateway writes with.
 *
 * A line this parser refuses is counted apart rather than skipped, because a scrub that silently dropped
 * bytes it could not read would otherwise be reported here as a clean volume. Splitting that count by the
 * credential each refused line spells is what lets a difference between two readings be attributed to the
 * run rather than left as a number that moved.
 */
export async function readVolume(dir: string, subject?: string): Promise<VolumeFacts> {
  const names = (await readdir(dir)).sort();
  const byCredential: Record<string, number> = {};
  let lines = 0;
  let unreadable = 0;
  let unreadableNaming = 0;
  let unreadableElsewhere = 0;
  const unreadableSamples: string[] = [];
  for (const name of names) {
    if (!name.startsWith('access-') || !name.endsWith('.jsonl')) continue;
    const text = await readFile(join(dir, name), 'utf8');
    for (const line of text.split('\n')) {
      if (line.length === 0) continue;
      lines += 1;
      let parsed: AccessRecord;
      try {
        parsed = parseAccessLine(line);
      } catch {
        unreadable += 1;
        if (subject !== undefined && line.includes(`"cred":"${subject}"`)) {
          unreadableNaming += 1;
        } else {
          unreadableElsewhere += 1;
        }
        if (unreadableSamples.length < 6) unreadableSamples.push(`${name} ${line.slice(0, 56)}`);
        continue;
      }
      const who = parsed.cred ?? '<no credential named>';
      byCredential[who] = (byCredential[who] ?? 0) + 1;
    }
  }
  return {
    names,
    lines,
    unreadable,
    unreadableNaming,
    unreadableElsewhere,
    unreadableSamples,
    byCredential,
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
