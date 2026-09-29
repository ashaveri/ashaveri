import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { generateSigningKey, sealDeploymentManifest, toHex } from '@ashaveri/receipt';
import {
  PUBLISHED_PAYLOAD,
  RECEIPT_PUBLIC_B64URL,
  absent,
  anchorReceiptOf,
  carriedObject,
  held,
  packCarrying,
  packOf,
} from './carried-pack.js';

/**
 * What `verify-handover` prints when a document, a receipt or a command line hands it text it did not write.
 *
 * The report is rows, and a row is the unit a reader of it splits lines on. Most of what the rows print is
 * figures, digests and identifiers the format validated before this command saw them, and four of the figures
 * are not: a record's id as the pack spells it, an absent anchor slot's reason as the collector wrote it inside a
 * sealed receipt, the caller's own spelling of the origin, the identity and the rung, and the vendor's words out
 * of the carried bytes. None of those is bounded below a length or checked for what characters it contains, and
 * the first two arrive from the party being verified rather than from the reader.
 *
 * So each of them is quoted on the shared cell rule before it joins a row, and every row of the report is escaped
 * again on its way to the stream. The second guard is the one that answers for the rows this file has not
 * enumerated, an export's assessment sentence and a manifest's issuer among them, and the last case below makes
 * one of those rows say what that guard is for.
 *
 * The JSON shape is not asserted to quote anything, because a port reads the token exactly: `writeJson` escapes
 * the quoted spans of what it serializes, and the cases here check that a token survives escaping whole rather
 * than that it is shown inside quotes.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-carried-collateral-'));
afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(args: string[]): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 15_000,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

let writtenCount = 0;
function written(name: string, data: Uint8Array | string): string {
  const path = join(tempDir, `${writtenCount++}-${name}`);
  writeFileSync(path, data);
  return path;
}

function verdictOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/**
 * The characters the shared guard classifies, one code point at a time, with the newline left out because a row is
 * allowed to end with one. A row count is paired with this everywhere it matters: the two together say the only
 * line endings in the report are the ones this program wrote between its own rows.
 */
function rawInvisible(text: string): string[] {
  return [...text].filter(
    (each) => each !== '\n' && /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/u.test(each),
  );
}

/** How many rows a reader that splits on any of the four line terminators would count. */
function jsRows(text: string): number {
  return text.split(/[\n\r\u2028\u2029]/u).filter((each) => each.length > 0).length;
}

/** How many rows this command wrote, counted the way its own source writes them. */
function writtenRows(text: string): number {
  return text.split('\n').filter((each) => each.length > 0).length;
}

/** The rows that begin at column zero: the two header lines, and nothing a document smuggled past the guard. */
function rowsAtColumnZero(text: string): string[] {
  return text.split('\n').filter((each) => each.length > 0 && !each.startsWith('  '));
}

/** The instant one record is chained under, and so the moment the carried material is read against. */
const IAT = 1_750_000_000;

/** A forged row, spelled the way a row of this report is spelled, so a guard that missed it would be visible. */
const FORGED = 'FORGED  signature  holds under a root nobody pinned';

/** A record id: a newline that would start a row, and a mark that would reorder the rest of the one it is on. */
const HOSTILE_ID = `receipt-0\n${FORGED}\u202e`;

/** An absence reason: the same two, plus the C1 next-line, which no property class of the old guard missed. */
const HOSTILE_REASON = `the collector read no window\n${FORGED}\u0085`;

const HOSTILE_ORIGIN = `intel-tcb-info\n${FORGED}`;

/** Bytes no vendor signed, for the rows that print what the appraisal met rather than what it read. */
const UNSIGNED = new TextEncoder().encode('a document nothing signed');

describe('the rows a pack, a receipt or a command line writes', () => {
  it('keeps a record id that carries a newline inside the rows it is printed on', () => {
    // The id is the store's own name for a record and the format bounds it in bytes alone, so it reaches the
    // report as the deployment spelled it. This command prints it on three rows: the run of records the pack
    // seals, the clause naming the slots that digest the material, and the label of that row. The row count is
    // the assertion, because a newline in an id would be a row this command never wrote.
    const receipt = anchorReceiptOf({ col: held(UNSIGNED), val: absent('the collector read no window') }, IAT);
    const path = written('hostile-id.cbor', packOf([{ id: HOSTILE_ID, iat: IAT, receipt }], [carriedObject(UNSIGNED)]));
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(rawInvisible(human.stdout)).toEqual([]);
    expect(jsRows(human.stdout)).toBe(writtenRows(human.stdout));
    expect(rowsAtColumnZero(human.stdout).map((one) => one.split(':')[0])).toEqual(['content type', 'read by']);

    // Quoted in the rows this command composes from foreign figures, and escaped whole in the older row that
    // prints the run: the label rule is for a token inside a row, and the stream guard is for a token that is
    // the row's own subject. Neither prints the newline the document carried as a line ending.
    expect(human.stdout).toMatch(/"receipt-0\\nFORGED[^\n]*\\u202e"/u);
    expect(human.stdout).toContain('receipt-0\\u000aFORGED');
  });

  it('keeps an absent slot reason inside the clause that names the slot', () => {
    // An absence is the collector's own sentence, required by the format and read as text and nothing more, and
    // it is printed in the clause that says which slot stated it. A newline inside it would end that clause and
    // start a row of its own.
    const receipt = anchorReceiptOf({ col: held(UNSIGNED), val: absent(HOSTILE_REASON) }, IAT);
    const path = written('hostile-reason.cbor', packOf([{ id: 'receipt-0', iat: IAT, receipt }], [carriedObject(UNSIGNED)]));
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(rawInvisible(human.stdout)).toEqual([]);
    expect(jsRows(human.stdout)).toBe(writtenRows(human.stdout));
    expect(human.stdout).toContain('anchor absences:  receipt-0 at val:');
    expect(human.stdout).toMatch(/"the collector read no window\\nFORGED[^\n]*\\u0085"/u);

    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    const absences = (json.document as { anchorAbsences: { reason: string }[] }).anchorAbsences;
    // The machine shape keeps the reason whole: an escape is the other spelling of the same character to anything
    // that parses the document, and a port is owed the sentence rather than its bounds.
    expect(absences[0]?.reason).toBe(HOSTILE_REASON);
  });

  it('quotes the origin as the caller spelled it', () => {
    // The origin is typed at this command line and matched against the package's own list only when the answer is
    // formed, so nothing has validated its characters by the time it is printed back. Both rows that carry it are
    // checked: the fields the question was built from, and the question itself beside the digest it was asked of.
    const { pack } = packCarrying(UNSIGNED, IAT);
    const path = written('hostile-argv.cbor', pack);
    const human = runCli([
      'verify-handover',
      path,
      `--key=${RECEIPT_PUBLIC_B64URL}`,
      `--collateral-origin=col=${HOSTILE_ORIGIN}`,
      '--collateral-platform=col=tdx',
    ]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(rawInvisible(human.stdout)).toEqual([]);
    expect(jsRows(human.stdout)).toBe(writtenRows(human.stdout));
    expect(human.stdout).toContain('collateral fields:');
    expect(human.stdout).toContain('weighed as origin');
    expect(human.stdout).toMatch(/"intel-tcb-info\\nFORGED/u);

    const json = verdictOf(runCli([
      'verify-handover',
      path,
      `--key=${RECEIPT_PUBLIC_B64URL}`,
      `--collateral-origin=col=${HOSTILE_ORIGIN}`,
      '--collateral-platform=col=tdx',
      '--json',
    ]));
    const weighed = Object.entries(json.document as Record<string, unknown>).find(([key]) => key.startsWith('carried-'));
    const question = (weighed?.[1] as { question: { origin: string; cpuType: string | null } } | undefined)?.question;
    // The printed row shows the token's bounds; the port reads the token itself, newline and all.
    expect(question?.origin).toBe(HOSTILE_ORIGIN);
    expect(question?.cpuType).toBeNull();
  });

  it('escapes every row of the report, including the ones a document writes for itself', () => {
    // A deployment manifest's issuer is a string the SDK reads as non-empty and nothing else, and the row that
    // prints it was written before any collateral flag existed and carries no designation of this run's. It is
    // the case that says where the second guard sits: not on a list of rows this file keeps correct, but on the
    // one place every row reaches the stream, so a row added beside it is guarded whether or not anybody
    // remembered to name it here.
    const key = generateSigningKey();
    const designated = Buffer.from(key.publicKey).toString('base64url');
    const body = JSON.stringify({
      v: 1,
      iss: `acme\u0085region\n${FORGED}`,
      ins: PUBLISHED_PAYLOAD.ins,
      epk: PUBLISHED_PAYLOAD.epk,
      keys: [{ kid: toHex(key.kid), alg: 'Ed25519', publicKey: designated }],
      models: [{ id: PUBLISHED_PAYLOAD.mdl, wts: toHex(PUBLISHED_PAYLOAD.wts) }],
      meas: { tee: PUBLISHED_PAYLOAD.meas.tee, m: toHex(PUBLISHED_PAYLOAD.meas.m) },
    });
    const path = written('hostile-manifest.cbor', Buffer.from(sealDeploymentManifest(new TextEncoder().encode(body), key)));
    const human = runCli(['verify-handover', path, `--manifest-key=${designated}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(rawInvisible(human.stdout)).toEqual([]);
    expect(jsRows(human.stdout)).toBe(writtenRows(human.stdout));
    expect(rowsAtColumnZero(human.stdout)).toHaveLength(2);
    expect(human.stdout).toMatch(/issuer:\s+acme\\u0085region\\u000aFORGED/u);
  });
});
