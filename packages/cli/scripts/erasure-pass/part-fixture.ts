import { createHash } from 'node:crypto';
import { renderAccessLine } from '@ashaveri/signerd';

/**
 * The fixture's own timeline. Every generated line carries a stamp from here and every part a name
 * built from this day, both fixed, so a run's bytes depend on nothing but their seeds: two runs of this
 * directory can be compared, and a number that moved between them moved because the machine did.
 *
 * The day is in the past so that the retention sweep of a log directory can never age a fixture out
 * from under a run that is still reading it.
 */
const FIXTURE_DAY = '2026-03-01';
const FIXTURE_T = Date.parse(`${FIXTURE_DAY}T00:00:00.000Z`);

/** The subject's records are a fifth of a busy day's log, which is the shape a scrub is written for. */
const SUBJECT_EVERY = 5;

/**
 * Two kinds of line a whole-log walk has to survive unchanged, at fixed intervals so parts of one size
 * differ from each other in content while holding the same length and the same counts.
 *
 * The unparseable one is the promise the scrub makes about bytes it cannot read: a tool that quietly
 * discarded them would turn the erasure of one credential into the deletion of somebody else's records,
 * so `kept` counts it and every pass has to leave it standing exactly as it was found. The other is
 * valid JSON that is not an access record at all and names the subject in the one field the scrub
 * reads, so it goes. Neither can come from this gateway's own writer: the field allowlist in
 * `gateway/src/access-record.ts` has no place for the text these carry, which is the point of having
 * them here.
 *
 * Both carry multi-byte characters, and that is the other thing they are for. Every field a gateway
 * writes is ASCII (credential ids are held to `[A-Za-z0-9_-]`, request ids and receipts are hex or
 * base64url) so the only multi-byte bytes a part can hold are foreign ones, and a pass that reads the
 * file in blocks has to be able to be wrong about where a block ends. Splitting a multi-byte character
 * between two blocks is how a scrub silently rewrites `é` into `` and reports success while doing it,
 * so these two lines are where that is caught.
 */
const UNPARSEABLE_EVERY = 401;
const FOREIGN_SUBJECT_EVERY = 709;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hexOf(value: number): string {
  return Math.floor(value * 0xffffff)
    .toString(16)
    .padStart(6, '0');
}

export interface GeneratedPart {
  name: string;
  bytes: Buffer;
  /** Lines in the file, counting the ones no access-log reader would accept. */
  lines: number;
  /** Lines a scrub of `credential` has to remove, tallied here rather than by a pass over the file. */
  subjectLines: number;
  /** `lines` minus `subjectLines`: what has to stand in the rewritten part, byte for byte. */
  keptLines: number;
  sha256: string;
  /** The length the part has to be afterwards, which is the other half of the digest below. */
  keptBytes: number;
  /**
   * The digest the part has to carry afterwards, computed here from the lines this generator wrote and
   * never from a pass over the file. Every shape in the run is checked against it, which is what lets the
   * three numbers be compared at all: a chunked pass that re-spelled a line it could not read, or that
   * lost one it should have kept, changes this value and stops the run where it stands.
   */
  keptSha256: string;
}

/** The name a gateway writes and the retention sweep collects, in the only shape either accepts. */
export function partName(index: number): string {
  return `access-${FIXTURE_DAY}-${String(index).padStart(3, '0')}.jsonl`;
}

/** The id the fixture erases. In the credential id's own character class, as every real one is. */
export function subjectCredential(seed: number): string {
  return `subject-${hexOf(mulberry32(seed)())}`;
}

/** The day's other credentials, which a scrub has no business touching. */
function otherCredentials(seed: number): string[] {
  const rand = mulberry32(seed);
  return Array.from({ length: 7 }, (_, i) => `peer-${hexOf(rand())}-${String(i)}`);
}

/**
 * One part of at least `targetBytes`, cut at the last whole line.
 *
 * Cutting rather than padding keeps the sizes honest: a part whose final line is a partial record is a
 * part this gateway's own rotation at `MAX_ACCESS_FILE_BYTES` never writes, and a pass tested against
 * one has tested a shape nobody has to survive. The result is a few hundred bytes short of the size it
 * is named for, which is stated next to every number that comes from it.
 */
export function generatePart(index: number, seed: number, targetBytes: number, credential: string): GeneratedPart {
  const rand = mulberry32(seed);
  const held = otherCredentials(seed);
  const lines: string[] = [];
  let bytes = 0;
  for (let at = 0; bytes < targetBytes; at += 1) {
    let line: string;
    if (at > 0 && at % UNPARSEABLE_EVERY === 0) {
      line = `{"cred":"${credential}","note":"coupée en writing \u{1F600}`;
    } else if (at > 0 && at % FOREIGN_SUBJECT_EVERY === 0) {
      line = `{"cred":"${credential}","written_by":"un autre système \u{1F989}"}`;
    } else {
      line = renderAccessLine({
        t: FIXTURE_T + at * 3,
        rid: `${hexOf(rand())}${hexOf(rand())}-${String(at)}`,
        cred: at % SUBJECT_EVERY === 0 ? credential : (held[at % held.length] as string),
        auth: at % 3 === 0 ? 'bearer' : 'pop',
        scope: at % 7 === 0 ? 'read' : 'complete',
        m: 'POST',
        p: at % 13 === 0 ? '/v1/receipts/0123456789abcdef' : '/v1/chat/completions',
        rcp: at % 11 === 0 ? null : `${hexOf(rand())}${hexOf(rand())}${hexOf(rand())}`,
        nce: `${hexOf(rand())}${hexOf(rand())}${hexOf(rand())}`,
        st: at % 23 === 0 ? 429 : 200,
        dur: 1 + Math.floor(rand() * 900),
        deny: at % 23 === 0 ? 'RATE_LIMITED' : null,
      }).replace(/\n$/u, '');
    }
    const withNewline = `${line}\n`;
    const length = Buffer.byteLength(withNewline);
    if (bytes + length > targetBytes && lines.length > 0) break;
    lines.push(withNewline);
    bytes += length;
  }
  const buffer = Buffer.from(lines.join(''), 'utf8');
  // The part a pass owes is the kept lines joined and terminated, which is what the whole-file pass
  // writes and what the chunked pass writes batch by batch; the two agree only because a kept line is
  // never empty, so no separator is left standing on its own.
  const kept = lines
    .map((line) => line.replace(/\n$/u, ''))
    .filter((line) => line.length > 0 && !namesSubject(line, credential));
  const keptText = kept.length === 0 ? '' : `${kept.join('\n')}\n`;
  const subjectLines = lines.filter((each) => namesSubject(each, credential)).length;
  return {
    name: partName(index),
    bytes: buffer,
    lines: lines.length,
    subjectLines,
    keptLines: kept.length,
    sha256: createHash('sha256').update(buffer).digest('hex'),
    keptBytes: Buffer.byteLength(keptText, 'utf8'),
    keptSha256: createHash('sha256').update(Buffer.from(keptText, 'utf8')).digest('hex'),
  };
}

/**
 * The one reading rule a pass is allowed to apply: a line is the subject's exactly when it parses and
 * its `cred` names the credential. Restated here, and not imported from where a pass runs it, so the
 * fixture's independent tally of `subjectLines` is not the same computation as the thing it checks.
 */
function namesSubject(line: string, credential: string): boolean {
  try {
    return (JSON.parse(line) as { cred?: unknown }).cred === credential;
  } catch {
    return false;
  }
}
