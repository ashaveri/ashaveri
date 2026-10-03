import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { generateSigningKey, sealDeploymentManifest, toHex } from '@ashaveri/receipt';
import { secondsOf, servedAnswer, servedChainOf, signedDocument, tcbInfo, testVendor } from '@ashaveri/fixtures';
import {
  PUBLISHED_PAYLOAD,
  RECEIPT_PUBLIC_B64URL,
  absent,
  anchorReceiptOf,
  attachedObject,
  digestHexOf,
  held,
  packAttaching,
  packManifestOf,
  packOf,
  sealPackManifest,
  servedCarriedPack,
  type PackEntry,
} from './carried-pack.js';
import { noteSpawn, spawnCeilingForCalls } from './support/spawn-budget.js';
/** How long one child of the built CLI may live before this file calls it a bug rather than a slow machine. */
const SPAWN_DEADLINE_MS = 15_000;

/**
 * What `verify-handover` prints when a document, a receipt or a command line hands it text it did not write.
 *
 * The report is rows, and a row is the unit a reader of it splits lines on. Most of what the rows print is
 * figures, digests and identifiers the format validated before this command saw them, and four of the figures
 * are not: a record's id as the pack spells it, an absent anchor slot's reason as the collector wrote it inside a
 * sealed receipt, the caller's own spelling of the origin, the identity and the rung, and the vendor's words out
 * of the attached bytes. None of those is bounded below a length or checked for what characters it contains, and
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
 *
 * Past the guards sit the weighing and the refusals it is reached by, each described with the cases that make it.
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
  noteSpawn(SPAWN_DEADLINE_MS);
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: SPAWN_DEADLINE_MS,
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

/** The instant one record is chained under, and so the moment the attached material is read against. */
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
    const path = written('hostile-id.cbor', packOf([{ id: HOSTILE_ID, iat: IAT, receipt }], [attachedObject(UNSIGNED)]));
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
    const path = written('hostile-reason.cbor', packOf([{ id: 'receipt-0', iat: IAT, receipt }], [attachedObject(UNSIGNED)]));
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
    const { pack } = packAttaching(UNSIGNED, IAT);
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
    const weighed = Object.entries(json.document as Record<string, unknown>).find(([key]) => key.startsWith('attached-'));
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

/**
 * The weighing itself, and the four ways an arm entry can disagree with the references beside it.
 *
 * Three of the four are refusals of the document and one is not, which is the distinction the arm's own codes
 * draw: an entry misstating its bytes, holding one digest twice, or holding material no reference of this pack
 * signs for is a container that contradicts itself, and the reader says so before it reports anything about the
 * span. What the reader never refuses is the arm coming up short of the references: a pack that refers to a held
 * slot and attaches nothing for it is whole, and the refusal there is the lookup's, at the digest the caller
 * reached for. So the fourth case below hands the command line that whole document and an arm short of one of its
 * references, and the answer it expects is a row naming the record, the slot and the digest rather than a position
 * of a list and rather than a refusal.
 *
 * The refusals are reached the way a customer reaches them: one pack is sealed honest, the next differs from it
 * in the one position its row names, and both are handed to the same command line. Each pair is pinned both ways
 * because a fault case on its own says only that something was refused: the accepted neighbour is what says the
 * refusal is about the position and not about the document.
 *
 * The material weighed in the accepted runs is of three kinds. Where a case is about the container, the bytes are a
 * sentence no vendor signed, and the answer the row prints is the reader's refusal to read it. Where a case is about
 * an envelope that carries its own certificates, the bytes are a TCB Info document signed by a test vendor whose root
 * the run pins through `--intel-root`, built by the vendor module `@ashaveri/fixtures` exports and the collateral
 * package's own cases import, because a window and a status can only be printed by an appraisal that believed a
 * signature. Where a case is about the answer a service actually returns, the bytes are that same statement's served
 * wrapper beside the issuer-chain header that module spells for it, because the half that reaches a root sits outside
 * the body and only the arm can hand it over. No case here reaches a network.
 */

/** The identity the document covers and the run asks by, as Intel's own documents spell both. */
const FMSPC = '00906e1b0d00';
const ISSUE_DATE = '2025-01-01T00:00:00Z';
const NEXT_UPDATE = '2027-01-01T00:00:00Z';
const TCB_DATE = '2025-06-01T00:00:00Z';
const LEVEL = `tcb-date=${TCB_DATE}`;

/** The instant the naming record is chained at, which is both the held instant and the moment weighed. */
const IAT_ISO = '2025-06-15T15:06:40.000Z';

const VENDOR = testVendor({
  notBefore: secondsOf('2020-01-01T00:00:00.000Z'),
  notAfter: secondsOf('2035-01-01T00:00:00.000Z'),
});

/** The statement the vendor signs, spelled once because two envelopes are written out of it below. */
const TCB_STATEMENT = tcbInfo({
  fmspc: FMSPC,
  issueDate: ISSUE_DATE,
  nextUpdate: NEXT_UPDATE,
  levels: [{ tcbDate: TCB_DATE, tcbStatus: 'UpToDate' }],
});

/** The signed statement the pack attaches, and the root this run pins beside it. */
const TCB_DOCUMENT = signedDocument(TCB_STATEMENT, VENDOR);

/**
 * The same statement as this vendor's service answers it: a wrapper body holding the document member and a hex
 * `signature` member with no certificate inside it, beside the issuer-chain header that arrived with the response.
 * That pair is what the arm's chain half and a reference's `c` exist for, and the case below is where a shipped
 * command weighs it.
 */
const SERVED_TCB = servedAnswer(TCB_STATEMENT, 'tcbInfo', VENDOR);
const ROOT_PATH = written('intel-root.der', VENDOR.rootDer);

/** The five flags that make one slot weighable, as a customer spells them. */
function designation(slot: string): string[] {
  return [
    `--intel-root=${ROOT_PATH}`,
    `--collateral-origin=${slot}=intel-tcb-info`,
    `--collateral-platform=${slot}=tdx`,
    `--collateral-cpu-type=${slot}=${FMSPC}`,
    `--collateral-level=${slot}=${LEVEL}`,
  ];
}

/** The window as seconds, which is how the machine shape prints it and the row prints its two ends. */
const WINDOW_FROM = Math.floor(Date.parse(ISSUE_DATE) / 1000);
const WINDOW_UNTIL = Math.floor(Date.parse(NEXT_UPDATE) / 1000);

/** Two distinct pieces of material, so an arm entry can name one and contradict the other. */
const MATERIAL_A = new TextEncoder().encode('the signed statement two records name at col');
const MATERIAL_B = new TextEncoder().encode('the validity window the appraisal above was published in');

/** Two sealed records whose anchors both take in the same pair: the shape the deduplication rule is for. */
function twoRecordsNamingBoth(): PackEntry[] {
  const slots = { col: held(MATERIAL_A), val: held(MATERIAL_B) };
  return [
    { id: 'receipt-0', iat: IAT, receipt: anchorReceiptOf(slots, IAT) },
    { id: 'receipt-1', iat: IAT + 1, receipt: anchorReceiptOf(slots, IAT + 1) },
  ];
}

/** The honest arm for those records, and the four ways it can disagree with the references beside it. */
const ATTACHED_BOTH = [attachedObject(MATERIAL_A), attachedObject(MATERIAL_B)];
const HONEST = packOf(twoRecordsNamingBoth(), ATTACHED_BOTH);

const MISSTATES_ITS_BYTES = sealPackManifest(packManifestOf(twoRecordsNamingBoth(), [
  attachedObject(MATERIAL_A),
  // The bytes of the second object under the first object's digest: the entry misstates the material inside it.
  { bytes: MATERIAL_B, sha256: attachedObject(MATERIAL_A).sha256, chain: null, chainSha256: null },
]));

const ONE_DIGEST_TWICE = sealPackManifest(packManifestOf(twoRecordsNamingBoth(), [
  attachedObject(MATERIAL_A),
  attachedObject(MATERIAL_A),
  attachedObject(MATERIAL_B),
]));

const NAMED_BY_NO_SLOT = sealPackManifest(packManifestOf(twoRecordsNamingBoth(), [
  attachedObject(MATERIAL_A),
  attachedObject(MATERIAL_B),
  attachedObject(new TextEncoder().encode('a document no sealed receipt of this pack names')),
]));

// The arm one object short: both records name `MATERIAL_B` at `val`, both references stand, and nothing attached
// hashes to that digest. The reader takes the document, because a pack that attaches less than it refers to has
// undertaken to hand over less and not more. The refusal is the weighing's, at the lookup.
const SHORT_BY_ONE_REFERENCE = sealPackManifest(packManifestOf(twoRecordsNamingBoth(), [attachedObject(MATERIAL_A)]));

/** The digest of one material, spelled the way the report spells it. */
const DIGEST_A = digestHexOf(MATERIAL_A);
const DIGEST_B = digestHexOf(MATERIAL_B);

/**
 * One refusal pair: the document that meets it and the honest one it differs from by one statement.
 *
 * `where` is the part of the sentence that says what was reached: a position of the arm for the three faults the
 * reader finds in a document, and the record, the slot and the digest for the answer the lookup gives when the arm
 * is short and the document is whole.
 */
function expectRefusedAndNeighbour(fault: Uint8Array, code: string, where: string): void {
  const path = written('fault.cbor', fault);
  const json = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
  expect(json.status).toBe(1);
  expect(verdictOf(json)).toMatchObject({ ok: false, contentType: 'ashaveri/pack', code });
  expect(String(verdictOf(json).message)).toContain(where);

  const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
  expect(human.status).toBe(1);
  expect(human.stdout).toBe('');
  expect(human.stderr).toContain(`(${code})`);
  expect(human.stderr).toContain(where);

  const neighbour = written('honest.cbor', HONEST);
  const accepted = runCli(['verify-handover', neighbour, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
  expect(accepted.stderr).toBe('');
  expect(accepted.status).toBe(0);
  expect(verdictOf(accepted).ok).toBe(true);
}

describe('the four ways an arm can disagree with the references beside it', () => {
  it('refuses an attached object that misstates the bytes inside it, and accepts the pack beside it', () => {
    expectRefusedAndNeighbour(MISSTATES_ITS_BYTES, 'PACK_ATTACHED_DIGEST_MISMATCH', 'attached[1] states');
  });

  it('refuses one digest attached at two positions, and accepts the pack beside it', () => {
    expectRefusedAndNeighbour(ONE_DIGEST_TWICE, 'PACK_ATTACHED_DUPLICATE', `attached[1] repeats the digest ${DIGEST_A} already attached at attached[0]`);
  });

  it('refuses an attached object no reference of this pack signs for, and accepts the pack beside it', () => {
    expectRefusedAndNeighbour(NAMED_BY_NO_SLOT, 'PACK_ATTACHED_UNNAMED', 'attached[2] holds');
  });

  it('answers for a held slot the arm leaves empty with a row that says so, and not with a refusal', () => {
    // The format takes this document: a pack that refers to a held slot and attaches no copy of it has stated less
    // rather than contradicted itself, so what such a pack gets is a row naming the digest, the slot, the record
    // and the fact that nothing was weighed against it, and not a refusal.
    const path = written('arm-short.cbor', SHORT_BY_ONE_REFERENCE);
    const json = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
    expect(json.status).toBe(0);
    expect(verdictOf(json).ok).toBe(true);
    const document = verdictOf(json).document as Record<string, Record<string, unknown>>;
    expect(document[`attached-${DIGEST_A}`]).toMatchObject({ attached: true, attachedBytes: MATERIAL_A.byteLength, weighed: false });
    expect(document[`attached-${DIGEST_B}`]).toMatchObject({
      digest: DIGEST_B,
      item: 'receipt-0',
      slot: 'val',
      attached: false,
      attachedBytes: null,
      weighed: false,
      state: null,
      question: null,
      notWeighed: expect.stringContaining('receipt-0 at val states this digest and the pack attaches no object hashing to it'),
    });
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.status).toBe(0);
    expect(human.stdout).toContain(`digest ${DIGEST_B}, attached by nothing in this pack, named by receipt-0 at val, receipt-1 at val`);
    expect(human.stdout).toContain(`digest ${DIGEST_A}, attached as ${String(MATERIAL_A.byteLength)} byte(s), named by receipt-0 at col, receipt-1 at col`);
  });
});

describe('a pack whose attached material is weighed', () => {
  it('weighs the material a held slot names and prints the digest, the naming record, the instant, the state and the window', () => {
    const { pack, digest } = packAttaching(TCB_DOCUMENT, IAT);
    const path = written('weighed.cbor', pack);
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col')]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    // The five figures this step exists to state, each in the row that carries it.
    expect(human.stdout).toContain(`digest ${digest}, attached as ${String(TCB_DOCUMENT.byteLength)} byte(s), named by receipt-0 at col`);
    expect(human.stdout).toContain(`read against ${String(IAT)} (${IAT_ISO}), the stamp receipt-0 was chained at`);
    expect(human.stdout).toContain('answered stale');
    expect(human.stdout).toContain(`the vendor's words read trusted as UpToDate, under the pinned anchor ${VENDOR.rootDigest}`);
    expect(human.stdout).toContain(`the window it signed runs ${ISSUE_DATE.replace('Z', '.000Z')} to ${NEXT_UPDATE.replace('Z', '.000Z')}, read against ${IAT_ISO}`);
    expect(human.stdout).toContain('refused COLLATERAL_NOT_OBSERVED for retained:');
    // The rule the roots are read under, stated whether or not any were handed.
    expect(human.stdout).toContain('1 --intel-root file(s) handed');
    expect(human.stdout).toContain('no root bundled with the verifier is consulted on this path');

    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col'), '--json']));
    const row = (json.document as Record<string, Record<string, unknown>>)[`attached-${digest}`] ?? {};
    expect(row).toMatchObject({
      digest,
      item: 'receipt-0',
      slot: 'col',
      namedBy: [{ item: 'receipt-0', slot: 'col' }],
      attached: true,
      attachedBytes: TCB_DOCUMENT.byteLength,
      appraisalAt: IAT,
      heldAt: IAT,
      environment: PUBLISHED_PAYLOAD.meas.tee,
      question: { origin: 'intel-tcb-info', platform: 'tdx', cpuType: FMSPC, level: LEVEL, roots: 1 },
      weighed: true,
      notWeighed: null,
      state: 'stale',
      reach: 'historical-knowledge',
      readAs: 'trusted',
      vendorStatus: 'UpToDate',
      declaredCpuType: FMSPC,
      anchorDigest: VENDOR.rootDigest,
      window: { from: WINDOW_FROM, until: WINDOW_UNTIL },
      retainUntil: WINDOW_UNTIL,
      refusal: { code: 'COLLATERAL_NOT_OBSERVED', missing: ['retained'], verdict: 'terminal' },
    });
    // The seal line answers the container and nothing else: an appraisal that came back stale moves it not at all.
    expect(json.ok).toBe(true);
    expect((json.document as { signature: unknown }).signature).toBe(true);
  });

  it('weighs a served body beside the header that arrived with it, and refuses the pair whose header is another answer\'s', () => {
    // The embedded case above can be weighed from the body alone, because its certificates travel inside it. This
    // one cannot: the served body is the wrapper a service answers with, a document member and a hex signature and
    // no certificate anywhere, so the only half that reaches a root is the header the arm carries beside it and the
    // only thing tying them together is the digest the reference states for that header. The pair is therefore
    // asserted twice: once as the weighing it answers with, and once as the refusal a wrong header brings, because
    // a reader that never looked at the header would pass the first half and miss the second.
    const served = servedCarriedPack(SERVED_TCB.body, SERVED_TCB.chain, IAT);
    const path = written('served-pair.cbor', served.pack);
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col')]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain(`digest ${served.digest}, attached as ${String(SERVED_TCB.body.byteLength)} byte(s), named by receipt-0 at col`);
    expect(human.stdout).toContain('answered stale');
    expect(human.stdout).toContain(`under the pinned anchor ${VENDOR.rootDigest}`);

    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col'), '--json']));
    const row = (json.document as Record<string, Record<string, unknown>>)[`attached-${served.digest}`] ?? {};
    expect(row).toMatchObject({
      digest: served.digest,
      item: 'receipt-0',
      slot: 'col',
      attached: true,
      attachedBytes: served.bodyBytes,
      weighed: true,
      notWeighed: null,
      state: 'stale',
      readAs: 'trusted',
      vendorStatus: 'UpToDate',
      anchorDigest: VENDOR.rootDigest,
      window: { from: WINDOW_FROM, until: WINDOW_UNTIL },
    });
    // The absence beside it stays an absence: this record states no validity material, so no second row appears and
    // the served half is weighed once.
    expect(Object.keys(json.document as Record<string, unknown>).filter((key) => key.startsWith('attached-'))).toHaveLength(1);

    const otherChain = servedChainOf([VENDOR.rootDer, VENDOR.issuerDer]);
    const swapped = sealPackManifest(packManifestOf(
      served.entries,
      [attachedObject(SERVED_TCB.body, otherChain)],
      { a: 'served', c: new Uint8Array(Buffer.from(served.chainDigest, 'hex')) },
    ));
    const refused = runCli(['verify-handover', written('arm-chain-other-answer.cbor', swapped), `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col'), '--json']);
    expect(refused.status).toBe(1);
    expect(verdictOf(refused)).toMatchObject({ ok: false, contentType: 'ashaveri/pack', code: 'PACK_ATTACHED_DIGEST_MISMATCH' });
    expect(String(verdictOf(refused).message)).toContain('attached[0] carries a header digesting to');
    expect(String(verdictOf(refused).message)).toContain('receipt-0 at col');
  });

  it('weighs one object once however many sealed records name it', () => {
    const path = written('deduplicated.cbor', HONEST);
    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col'), '--json']));
    const document = json.document as Record<string, { digest: string; item: string; namedBy: { item: string; slot: string }[] }>;
    const rows = Object.entries(document).filter(([key]) => key.startsWith('attached-'));
    expect(rows).toHaveLength(2);
    const col = rows.find(([, value]) => value.digest === DIGEST_A);
    expect(col?.[1]?.namedBy).toEqual([
      { item: 'receipt-0', slot: 'col' },
      { item: 'receipt-1', slot: 'col' },
    ]);
    // One row per digest, named by every slot that states it: the pack holds the material once, and the two
    // records agree on which object each of them took in.
    expect(String(col?.[1]?.item)).toBe('receipt-0');
  });

  it('reports every held slot as not weighed when the run hands no designation, and exits as it did without the flags', () => {
    const path = written('undesigned.cbor', HONEST);
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain("not weighed, --collateral-origin and --collateral-platform named no 'col' question");
    expect(human.stdout).toContain("named no 'val' question");
    expect(human.stdout).toContain('no --intel-root was handed');
    expect(human.stdout).not.toContain('answered');

    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    const document = json.document as Record<string, Record<string, unknown>>;
    expect(document[`attached-${DIGEST_A}`]).toMatchObject({
      weighed: false,
      state: null,
      question: null,
      notWeighed: expect.stringContaining('--collateral-origin'),
    });
    // The same document, the same key, the same exit: nothing an appraisal could not answer moves the verdict the
    // format gave the container.
    const pinned = runCli(['verify-pack', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(pinned.status).toBe(0);
  });

  it('answers a CPU type the format cannot index by with the refusal that names the field', () => {
    // Twelve hex characters is what the address is built from, and the code that builds it says so: this command
    // keeps no second pattern, so the answer a caller gets is the package's own and it arrives as a row.
    const { pack, digest } = packAttaching(TCB_DOCUMENT, IAT);
    const path = written('short-key.cbor', pack);
    const args = [
      'verify-handover',
      path,
      `--key=${RECEIPT_PUBLIC_B64URL}`,
      `--intel-root=${ROOT_PATH}`,
      '--collateral-origin=col=intel-tcb-info',
      '--collateral-platform=col=tdx',
      '--collateral-cpu-type=col=00906e1b0d0',
      `--collateral-level=col=${LEVEL}`,
    ];
    const human = runCli(args);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain('cpuType 00906e1b0d0 is not twelve hex characters');
    expect(human.stdout).toContain('answered missing-context');

    const json = verdictOf(runCli([...args, '--json']));
    const row = (json.document as Record<string, Record<string, unknown>>)[`attached-${digest}`] ?? {};
    expect(row).toMatchObject({
      weighed: true,
      state: 'missing-context',
      readAs: null,
      vendorStatus: null,
      window: null,
      refusal: { code: 'COLLATERAL_INPUT_MISSING', missing: ['cpuType'], verdict: 'terminal' },
    });
  });

  it('refuses a held slot whose digest the format cannot state, before any lookup is keyed by it', () => {
    // Thirty-one bytes is a lookup key no attached object can hash to, and the width is settled where the slot is
    // read: the command never reaches the answer's own refusal because the seal names the position first.
    const receipt = anchorReceiptOf({ col: { presence: 'held', sha256: new Uint8Array(31) }, val: absent('the collector read no window') }, IAT);
    const path = written('short-digest.cbor', packOf([{ id: 'receipt-0', iat: IAT, receipt }], []));
    const result = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
    expect(result.status).toBe(1);
    expect(verdictOf(result)).toMatchObject({ ok: false, contentType: 'ashaveri/pack', code: 'PACK_RECEIPT_INVALID' });
    expect(String(verdictOf(result).message)).toContain('must be a 32-byte bstr');
  });

  it('discloses a designation the document in front of it carries no material for', () => {
    // Only a pack carries material a slot names, and a caller looping one line across a bundle hands these flags
    // to every file: the answer is that they were accepted and unused, in the report rather than in silence.
    const receipt = anchorReceiptOf({ col: held(MATERIAL_A), val: absent('the collector read no window') }, IAT);
    const path = written('standalone-receipt.cbor', receipt);
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col')]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain('not consulted:');
    expect(human.stdout).toContain('and ashaveri/receipt carries none');

    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, ...designation('col'), '--json']));
    const designations = json.keyDesignations as Record<string, unknown>[];
    expect(designations).toContainEqual({ consulted: false, contentType: 'ashaveri/receipt', roots: 1 });
  });

  it('states where each field of the question came from, and holds the absence rows in the machine shape', () => {
    const slots = { col: held(MATERIAL_A), val: absent(HOSTILE_REASON) };
    const path = written('fields.cbor', packOf([{ id: 'receipt-0', iat: IAT, receipt: anchorReceiptOf(slots, IAT) }], [attachedObject(MATERIAL_A)]));
    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    const document = json.document as Record<string, unknown>;
    expect(document.collateralRoots).toMatchObject({ handed: 0, files: [], bundledConsulted: false });
    const fields = document.collateralFields as { field: string; from: string }[];
    expect(fields.map((one) => one.field)).toEqual(['bytes', 'heldAt', 'appraisalAt', 'platform', 'cpuType', 'level', 'roots', 'onAbsent']);
    expect(String(fields[0]?.from)).toContain('resolveAttached');
    expect(String(fields[3]?.from)).toContain('--collateral-platform named none');
    expect(document.anchorAbsences).toMatchObject([{ item: 'receipt-0', slot: 'val', presence: 'absent-at-source' }]);
    expect(document.attached).toBeUndefined();
    // A row is only owed when nothing at all was weighed, and this pack weighed one object.
    expect(Object.keys(document).filter((key) => key.startsWith('attached-'))).toHaveLength(1);
  });
});

describe('the designations refused before the document is opened', () => {
  const path = written('args.cbor', HONEST);
  const key = `--key=${RECEIPT_PUBLIC_B64URL}`;

  /** The two lines a refusal at the argument edge owes: the exit, and the flag the message names. */
  function expectUsageRefusal(args: string[], phrase: string): void {
    const result = runCli(['verify-handover', path, key, ...args]);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr.startsWith('ashaveri: ')).toBe(true);
    expect(result.stderr).toContain(phrase);
    expect(result.stderr).toContain("Try 'ashaveri --help' for usage.");
  }

  it('refuses a value that states no slot before its separator', () => {
    expectUsageRefusal(['--collateral-origin=intel-tcb-info'], "--collateral-origin takes '<slot>=<value>'");
    expectUsageRefusal(['--collateral-origin=col='], "names the 'col' slot and states nothing for it");
    expectUsageRefusal(['--collateral-origin==tdx'], "names '', and a sealed receipt's anchor has two slots");
  });

  it('refuses a slot name no anchor has', () => {
    expectUsageRefusal(['--collateral-origin=validity=intel-tcb-info'], "names 'validity', and a sealed receipt's anchor has two slots: 'col' and 'val'");
    expectUsageRefusal(['--collateral-platform=x1=tdx'], "names 'x1', and a sealed receipt's anchor has two slots");
  });

  it('refuses an origin with no platform and a platform with no origin', () => {
    expectUsageRefusal(
      ['--collateral-origin=col=intel-tcb-info'],
      "--collateral-origin names the 'col' slot as intel-tcb-info, and --collateral-platform names no platform for it",
    );
    expectUsageRefusal(
      ['--collateral-platform=col=tdx'],
      "--collateral-platform names the 'col' slot, which --collateral-origin named no origin for",
    );
  });

  it('refuses a platform this package publishes no collateral for', () => {
    expectUsageRefusal(
      ['--collateral-platform=col=amd', '--collateral-origin=col=intel-tcb-info'],
      "--collateral-platform names 'amd' for the 'col' slot, and this package publishes collateral for sgx and tdx",
    );
  });

  it('refuses a level with no arm and a level with no value', () => {
    expectUsageRefusal(
      ['--collateral-level=col=2026-01-01', '--collateral-origin=col=intel-tcb-info', '--collateral-platform=col=tdx'],
      "names '2026-01-01' for the 'col' slot, and a level is asked by one of the two arms",
    );
    expectUsageRefusal(
      ['--collateral-level=col=tcb-date', '--collateral-origin=col=intel-tcb-info', '--collateral-platform=col=tdx'],
      "names 'tcb-date' for the 'col' slot and states no value for it",
    );
    expectUsageRefusal(
      ['--collateral-level=col=tcb-composition=', '--collateral-origin=col=intel-tcb-info', '--collateral-platform=col=tdx'],
      "names 'tcb-composition' for the 'col' slot and states no value for it",
    );
  });

  it(
    'refuses one slot named twice for one field, and accepts the same slot named by all four fields',
    { timeout: spawnCeilingForCalls(5, SPAWN_DEADLINE_MS) },
    () => {
    expectUsageRefusal(
      ['--collateral-origin=col=intel-tcb-info', '--collateral-origin=col=intel-qe-identity', '--collateral-platform=col=tdx'],
      "--collateral-origin names the 'col' slot twice, and a slot has one origin, which is the path the bytes were published by per run",
    );
    expectUsageRefusal(
      ['--collateral-level=col=tcb-date=2026-01-01T00:00:00Z', '--collateral-level=col=tcb-composition=00', '--collateral-origin=col=intel-tcb-info', '--collateral-platform=col=tdx'],
      "--collateral-level names the 'col' slot twice, and a slot has one level, which is one rung of the ladder per run",
    );
    expectUsageRefusal(
      ['--collateral-cpu-type=col=00906e1b0d00', '--collateral-cpu-type=col=00906e1b0d01', '--collateral-origin=col=intel-tcb-info', '--collateral-platform=col=tdx'],
      "--collateral-cpu-type names the 'col' slot twice, and a slot has one CPU type per run",
    );
    // The refusal reads the field, not the slot: one slot named by all four flags is the ordinary call, and the
    // other slot named by its own pair beside it is what a pack holding both halves asks for.
    const bothSlots = runCli([
      'verify-handover',
      path,
      key,
      ...designation('col'),
      '--collateral-origin=val=intel-tcb-info',
      '--collateral-platform=val=tdx',
    ]);
    expect(bothSlots.stderr).toBe('');
    expect(bothSlots.status).toBe(0);
    expect(bothSlots.stdout).toContain('weighed col receipt-0');
    expect(bothSlots.stdout).toContain('weighed val receipt-0');
    const oneSlot = runCli(['verify-handover', path, key, ...designation('col')]);
    expect(oneSlot.stderr).toBe('');
    expect(oneSlot.status).toBe(0);
  });
});
