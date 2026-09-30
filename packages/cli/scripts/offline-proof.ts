import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  RECEIPT_PUBLIC_B64URL,
  anchorReceiptOf,
  carriedObject,
  digestHexOf,
  held,
  packManifestOf,
  packOf,
  sealCarriedPack,
  PUBLISHED_PAYLOAD,
  type PackEntry,
} from '../test/carried-pack.ts';
import { secondsOf, signedDocument, tcbInfo, testVendor } from '../../collateral/test/support/collateral-documents.ts';

/**
 * The inputs the single-file verifier is proved against, written into a directory that holds nothing
 * else, and the verbs proved by running the artifact over the published pack, export and amendment.
 *
 * The CI job that runs the bundle needs a policy and a deployment manifest whose pins match the committed
 * receipt it is about to check, and this started life as a script pasted into the workflow file. That shape
 * is the reason it is a file now: a heredoc inside a job is read by no `tsconfig`, so a wrong field name in
 * it fails on a runner, in a pull request, with nothing local able to reach it first. As a script it is
 * typechecked with the rest of this package and runnable by hand, which is the only way the bundle's proof
 * can be observed anywhere other than Actions.
 *
 * The pack, the export and the amendment are proved here for that same reason, and they are proved by
 * running: the job reaches this file with one line, so a verb added to the bundle is only covered once
 * something in here starts a process with it. `verify-pack` and `verify-export` are the same reader over the
 * same bytes as `verify-handover` with one answer pinned, and a claim that a stranger can verify a pack with
 * nothing installed is about those two verbs as much as about the receipt. So each is run three times: over
 * its own document, over the other verb's, and over one where the material beside the document does not
 * answer for it. An amendment is run four times, because it is the one shape that arrives as a pair: read
 * against the pack it designates, refused with that pack left at home, refused by the verb that means a
 * pack, and answered as a pack when the pack itself is what the run was handed.
 *
 * Nothing is invented in those ten. Every value they read is read out of the committed vector, so the
 * generated document cannot state a pin the receipt does not carry, and the verification time is the
 * vector's own `iat` rather than the wall clock, because this is not re-issuing a receipt. Each assertion
 * below is read out of the report the artifact printed rather than out of its exit status, because a status
 * says that a command stopped and only the report says which document it stopped about and what it found.
 *
 * The material a pack carries is proved over a container built here rather than over a published vector,
 * and the reason is stated in the published bytes: `pack-v1.json` does carry a run whose held slots name
 * material (`collateral-carried-inside-the-pack`), but the objects it carries are the sentences
 * `pack-vectors.ts` writes, not a vendor's signed statement, so an appraisal of them can only answer that
 * it met something it cannot read. A window, a vendor status and a reached anchor are printed by an
 * appraisal that believed a signature, and no published fixture holds a signature this repository
 * publishes the root of. The container below is therefore assembled the way the generator assembles its
 * own: the receipts by `issueReceipt`, the pack by `signPack`, the mis-stated carried list by the same
 * piecewise seal the published fault rows are made of, and the collateral document by the vendor support
 * the collateral package's cases use. Its root is generated at run time, so what is asserted is the
 * reading of one signature by the run that pinned it and nothing about what any real vendor publishes.
 */

/** The committed signing key material a fixture receipt was issued under. */
interface FixtureKey {
  readonly kid: string;
  readonly publicKey: string;
}

/** The JSON rendering of the published valid receipt, whose payload the pins are read from. */
interface FixtureReceipt {
  readonly payload: {
    readonly iss: string;
    readonly ins: string;
    readonly mdl: string;
    readonly wts: string;
    readonly epk: number;
    readonly nce: string;
    readonly req: string;
    readonly res: string;
    readonly iat: number;
    readonly meas: { readonly tee: string; readonly m: string };
  };
}

/** Hex key bytes to the unpadded base64url spelling the manifest and the policy both use. */
function publicKeyFromHex(hex: string): string {
  if (!/^[0-9a-f]+$/u.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`the fixture key is not lowercase hex of whole bytes: ${hex}`);
  }
  return Buffer.from(hex, 'hex').toString('base64url');
}

/** One row of a published vector suite: the document, and whatever the row says a caller holds beside it. */
interface VectorRow {
  readonly name: string;
  readonly documentBase64Url: string;
  readonly read: {
    readonly pinned?: string;
    readonly companions?: readonly { readonly name: string; readonly bytesBase64Url: string }[];
  };
  /** The order the published reader reached the items in, on every pack row this proof reads. */
  readonly walk?: readonly string[];
  /** The pack an amendment row is checked against, as the whole sealed document. */
  readonly packBase64Url?: string;
  /** The records the published amendment leaves in the pack, in the order the pack's links fix them. */
  readonly survivors?: readonly string[];
  readonly reducedHex?: string;
  readonly originalHeadHex?: string;
}

/** The published pack suite, whose rows carry the key material the pack vectors are sealed under. */
interface PackVectorFile {
  readonly vectors: readonly VectorRow[];
}

/** The published export suite, which states the one key its rows are sealed under beside them. */
interface ExportVectorFile {
  readonly layout: { readonly key: { readonly publicKeyHex: string } };
  readonly vectors: readonly VectorRow[];
}

/** The published redaction suite, whose rows each carry the pack their amendment designates. */
interface RedactionVectorFile {
  readonly vectors: readonly VectorRow[];
}

function rowNamed(file: string, vectors: readonly VectorRow[], name: string): VectorRow {
  const row = vectors.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published ${file} has no vector named '${name}', so this proof would be asserting a document nothing publishes`);
  }
  return row;
}

/** A published field this proof cannot run without, refused by name rather than defaulted to nothing. */
function stated<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`the published suite states no ${what}, so this proof would be asserting a value nothing publishes`);
  }
  return value;
}

/**
 * The report a handover verb prints under `--json`, read for the members that carry its claim.
 *
 * `contentType` is absent on a refusal given before the document's type was settled, which is one of the
 * facts asserted below rather than one left to inference, so the field is optional here rather than
 * defaulted to something a run never printed.
 */
interface HandoverReport {
  readonly ok?: boolean;
  readonly contentType?: string;
  readonly reader?: string;
  readonly code?: string;
  readonly message?: string;
  readonly document?: {
    readonly walked?: { readonly walked: number; readonly declared: number };
    readonly items?: readonly { readonly id: string }[];
    readonly collection?: { readonly kind: string; readonly items: number };
    readonly originals?: readonly { readonly id: string; readonly sha256: string; readonly original: string }[];
    readonly survivors?: { readonly survivors: number; readonly declared: number };
    readonly survivorItems?: readonly { readonly id: string }[];
    readonly pack?: { readonly sha256: string };
    readonly reduced?: string;
    readonly originalHead?: string;
    readonly collateralRoots?: CollateralRootsRow;
  };
}

/**
 * The row stating the roots an appraisal of carried material was weighed under.
 *
 * `files` is the paths this run named, echoed back as handed, and `bundledConsulted` is the rule's own
 * answer rather than the run's: the artifact states in the same row that nothing it carries was consulted.
 * The refusal that answers a run which named no root is proved separately below, because that sentence is
 * the observable half of the rule and this field is the disclosure of it.
 */
interface CollateralRootsRow {
  readonly handed: number;
  readonly files: readonly string[];
  readonly bundledConsulted: boolean;
  readonly rule: string;
}

/** A refusal as the machine shape prints it: the code, the fields it names, and the verdict beside them. */
interface CarriedRefusalRow {
  readonly code: string;
  readonly missing: readonly string[];
  readonly detail: string;
  readonly verdict: string;
}

/**
 * One held slot's weighing, as `verify-pack` and `verify-handover` print it under `--json`.
 *
 * The figures come from three places and the row keeps them apart: the digest, the byte count and the
 * naming record's stamp are read out of the container, the question is the caller's own text, and the
 * state, the anchor digest, the window and the vendor's words are the appraisal's. A run asserting on
 * this shape is asserting on which of the three said what.
 */
interface CarriedRow {
  readonly digest: string;
  readonly item: string;
  readonly slot: string;
  readonly namedBy: readonly { readonly item: string; readonly slot: string }[];
  readonly carried: boolean;
  readonly carriedBytes: number;
  readonly appraisalAt: number;
  readonly heldAt: number;
  readonly environment: string;
  readonly question: {
    readonly origin: string;
    readonly platform: string;
    readonly cpuType: string | null;
    readonly level: string | null;
    readonly roots: number;
  } | null;
  readonly weighed: boolean;
  readonly notWeighed: string | null;
  readonly state: string | null;
  readonly reach: string | null;
  readonly readAs: string | null;
  readonly vendorStatus: string | null;
  readonly declaredCpuType: string | null;
  readonly anchorDigest: string | null;
  readonly window: { readonly from: number; readonly until: number } | null;
  readonly retainUntil: number | null;
  readonly refusal: CarriedRefusalRow | null;
}

/** One start of the artifact: the command line it was given, its status, and both streams. */
interface BundleRun {
  readonly args: readonly string[];
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** The artifact, under the name the proof directory knows it by, beside the documents it is proved over. */
const BUNDLE_NAME = 'ashaveri.mjs';

/** Where the bundle step writes the single file this proof runs: this script's own package's `dist`. */
const BUNDLE_SOURCE = fileURLToPath(new URL('../dist/ashaveri-bundle.mjs', import.meta.url));

function describeRun(run: BundleRun): string {
  return [
    `  command:  ashaveri.mjs ${run.args.join(' ')}`,
    `  exit:     ${String(run.status)}`,
    `  stdout:   ${run.stdout.trimEnd()}`,
    `  stderr:   ${run.stderr.trimEnd()}`,
  ].join('\n');
}

/** The one shape every failure here takes: what was wanted, and the whole run that refused to give it. */
function expect(condition: boolean, run: BundleRun, wanted: string): void {
  if (!condition) {
    throw new Error(`the bundled verifier did not ${wanted}\n${describeRun(run)}`);
  }
}

function say(line: string): void {
  process.stdout.write(`${line}\n`);
}

/**
 * One run of the artifact, from inside the proof directory and nowhere else.
 *
 * The working directory is the process's own `cwd`, so a bare specifier inside the bundle resolves the
 * way it would on a machine that has nothing installed: the directory has the file, the documents, the
 * root one run names and the four inputs, and no `node_modules` above it. A run that needed an installed
 * tree would fail here for the reason it would fail there, which is what makes these thirteen commands the
 * property the job exists to show rather than a restatement of it.
 */
function runBundle(workDir: string, args: readonly string[]): BundleRun {
  const result = spawnSync(process.execPath, [BUNDLE_NAME, ...args], {
    cwd: workDir,
    encoding: 'utf8',
    // The slowest of the thirteen runs below measures 192 ms here, which is one Node start, a pack with one
    // inner receipt, and the carried material read as a signature under the root that run named; the ceiling
    // is over a hundred and fifty times that, so a hang on a runner is a failure naming one command rather
    // than a job timeout naming a step.
    timeout: 30_000,
    killSignal: 'SIGKILL',
  });
  if (result.error !== undefined) {
    throw new Error(`could not run 'ashaveri.mjs ${args.join(' ')}': ${result.error.message}`);
  }
  return { args, status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function reportOf(run: BundleRun): HandoverReport {
  try {
    return JSON.parse(run.stdout) as HandoverReport;
  } catch (err) {
    throw new Error(
      `'ashaveri.mjs ${run.args.join(' ')}' printed no report to parse: ${err instanceof Error ? err.message : String(err)}\n${describeRun(run)}`,
    );
  }
}

/** What `verify-pack` is run over: its own document, a document that is not one, and one that is lying. */
interface PackCase {
  readonly whole: string;
  readonly edited: string;
  readonly wrongType: string;
  /** The key the published pack names in its header, and the export suite's key, which it does not. */
  readonly key: string;
  readonly otherKey: string;
  /** The item order the published row states the walk reached, which only the bytes can answer. */
  readonly walked: readonly string[];
}

/**
 * `ashaveri verify-pack` over the published pack: the reading, the refusal of another shape, and the
 * refusal of a pack whose contents disagree with the seal over them.
 */
function provePack(workDir: string, testCase: PackCase): void {
  const verdictRun = runBundle(workDir, ['verify-pack', `${testCase.whole}.cbor`, `--key=${testCase.key}`, '--json']);
  expect(verdictRun.status === 0, verdictRun, 'accept the published pack');
  const verdict = reportOf(verdictRun);
  expect(verdict.ok === true, verdictRun, 'report a pack it read as whole');
  expect(verdict.contentType === 'ashaveri/pack', verdictRun, 'name the content type the report is about');
  expect(verdict.reader === 'verifyPack', verdictRun, 'say which reader answered');
  const walked = (verdict.document?.items ?? []).map((one) => one.id).join(', ');
  expect(walked === testCase.walked.join(', '), verdictRun, `report the walk the published row states: it said '${walked}'`);
  expect(verdict.document?.walked?.walked === testCase.walked.length, verdictRun, 'count the items it walked at the figure the row publishes');
  say(`verify-pack ${testCase.whole}: exit 0, read by verifyPack as ashaveri/pack, walked ${walked}`);

  const editedRun = runBundle(workDir, ['verify-pack', `${testCase.edited}.cbor`, `--key=${testCase.key}`, '--json']);
  expect(editedRun.status === 1, editedRun, 'refuse a pack whose inner receipt was changed after the seal');
  const edited = reportOf(editedRun);
  expect(edited.ok === false, editedRun, 'report the edited pack as a refusal');
  expect(edited.contentType === 'ashaveri/pack', editedRun, 'name the type the pack it refused carried');
  expect(edited.code === 'INVALID_SIGNATURE', editedRun, `refuse with the signature code, gave ${String(edited.code)}`);
  say(`verify-pack ${testCase.edited}: exit 1, refused ${String(edited.code)}`);

  const wrongRun = runBundle(workDir, ['verify-pack', `${testCase.wrongType}.cbor`, `--key=${testCase.otherKey}`, '--json']);
  expect(wrongRun.status === 1, wrongRun, 'refuse the export document handed to the pack verb');
  const wrong = reportOf(wrongRun);
  expect(wrong.ok === false, wrongRun, 'report an export as a refusal for this verb');
  expect(wrong.contentType === undefined, wrongRun, 'stop before deciding which type the bytes are');
  expect(wrong.code === 'BAD_PROTECTED_HEADER', wrongRun, `refuse with the header code, gave ${String(wrong.code)}`);
  expect(wrong.message?.includes('typ=ashaveri/export') === true, wrongRun, 'name the type it found in the refusal');
  say(`verify-pack ${testCase.wrongType}: exit 1, refused ${String(wrong.code)} naming typ=ashaveri/export`);
}

/** What `verify-export` is run over, and the one original its item travels in. */
interface ExportCase {
  readonly document: string;
  readonly wrongType: string;
  readonly key: string;
  readonly otherKey: string;
  /** The companion file the published row hands over, and the digest of the bytes it holds. */
  readonly companion: string;
  readonly digest: string;
}

/**
 * `ashaveri verify-export` over the published export: the reading with the original beside it, the same
 * document refused without it, and the refusal of a pack.
 */
function proveExport(workDir: string, testCase: ExportCase): void {
  // Where the file sits on this disk. The option matches on the name at the end of the argument, which is
  // the name the signed item carries, so the directory in front of it is the caller's own arrangement.
  const companionPath = join(workDir, testCase.companion);
  const verdictRun = runBundle(workDir, [
    'verify-export',
    `${testCase.document}.cbor`,
    `--key=${testCase.key}`,
    `--companion=${companionPath}`,
    '--json',
  ]);
  expect(verdictRun.status === 0, verdictRun, 'accept the published export with its original beside it');
  const verdict = reportOf(verdictRun);
  expect(verdict.ok === true, verdictRun, 'report an export it read as whole');
  expect(verdict.contentType === 'ashaveri/export', verdictRun, 'name the content type the report is about');
  expect(verdict.reader === 'verifyExport', verdictRun, 'say which reader answered');
  const original = verdict.document?.originals?.[0];
  expect(original !== undefined, verdictRun, 'report the one original the published row carries');
  expect(original?.original === testCase.companion, verdictRun, `match the item to the file at its own name, saw ${String(original?.original)}`);
  expect(
    original?.sha256 === testCase.digest,
    verdictRun,
    'answer with the digest of the bytes handed over, so the reading ran over the file and not only over the header',
  );
  say(`verify-export ${testCase.document}: exit 0, read by verifyExport as ashaveri/export, ${testCase.companion} digested and matched`);

  const missingRun = runBundle(workDir, ['verify-export', `${testCase.document}.cbor`, `--key=${testCase.key}`, '--json']);
  expect(missingRun.status === 1, missingRun, 'refuse the same export with its original left at home');
  const missing = reportOf(missingRun);
  expect(missing.ok === false, missingRun, 'report an export whose original is absent as a refusal');
  expect(missing.code === 'EXPORT_ORIGINAL_UNAVAILABLE', missingRun, `refuse with the missing-original code, gave ${String(missing.code)}`);
  expect(missing.message?.includes(testCase.companion) === true, missingRun, 'name the file it looked for by the name the item carries');
  say(`verify-export ${testCase.document} without its companion: exit 1, refused ${String(missing.code)}`);

  const wrongRun = runBundle(workDir, ['verify-export', `${testCase.wrongType}.cbor`, `--key=${testCase.otherKey}`, '--json']);
  expect(wrongRun.status === 1, wrongRun, 'refuse the pack document handed to the export verb');
  const wrong = reportOf(wrongRun);
  expect(wrong.ok === false, wrongRun, 'report a pack as a refusal for this verb');
  expect(wrong.contentType === undefined, wrongRun, 'stop before deciding which type the bytes are');
  expect(wrong.code === 'BAD_PROTECTED_HEADER', wrongRun, `refuse with the header code, gave ${String(wrong.code)}`);
  expect(wrong.message?.includes('typ=ashaveri/pack') === true, wrongRun, 'name the type it found in the refusal');
  say(`verify-export ${testCase.wrongType}: exit 1, refused ${String(wrong.code)} naming typ=ashaveri/pack`);
}

/** What `verify-handover` is run over for the fifth shape: the amendment, the pack it names, and one key. */
interface RedactionCase {
  readonly document: string;
  /** The pack the published row states this amendment was checked against, already in the proof directory. */
  readonly pack: string;
  readonly key: string;
  /** The digest of the bytes the pack file holds, which is the designation the reader recomputes. */
  readonly packDigest: string;
  readonly survivors: readonly string[];
  readonly reduced: string;
  readonly originalHead: string;
}

/**
 * The fifth signed shape, run over a published pair: the amendment read against the pack it designates, the
 * same document refused with that pack left at home, the amendment refused by the verb that means a pack, and
 * the pack it speaks about answered as the pack it is.
 *
 * A redaction is the one shape of the five that arrives as a pair, and the pairing is what these runs are
 * about. The pack travels as bytes, its digest is recomputed by the reader and compared against the
 * designation inside the signature, and a run handed only one of the two says so by name rather than reading
 * an amendment on its own word. Both chain heads come back apart, because the pack's head still holds over
 * the pack's own run and the head over the survivors is a chain that pack does not contain.
 */
function proveRedaction(workDir: string, testCase: RedactionCase): void {
  const verdictRun = runBundle(workDir, [
    'verify-handover',
    `${testCase.document}.cbor`,
    `--key=${testCase.key}`,
    `--companion=${join(workDir, `${testCase.pack}.cbor`)}`,
    '--json',
  ]);
  expect(verdictRun.status === 0, verdictRun, 'accept the published amendment read against the pack it designates');
  const verdict = reportOf(verdictRun);
  expect(verdict.ok === true, verdictRun, 'report an amendment it read as whole');
  expect(verdict.contentType === 'ashaveri/redaction', verdictRun, 'name the content type the report is about');
  expect(verdict.reader === 'verifyRedaction', verdictRun, 'say which reader answered');
  const survivors = (verdict.document?.survivorItems ?? []).map((one) => one.id).join(', ');
  expect(survivors === testCase.survivors.join(', '), verdictRun, `report the survivor run the published row states, saw '${survivors}'`);
  expect(
    verdict.document?.pack?.sha256 === testCase.packDigest,
    verdictRun,
    'answer with the digest of the pack bytes handed over, so the reading ran over the file and not only over the header',
  );
  expect(verdict.document?.reduced === testCase.reduced, verdictRun, 'report the chain over the survivors as the row publishes it');
  expect(verdict.document?.originalHead === testCase.originalHead, verdictRun, 'report the pack head beside it, as a separate number');
  expect(
    verdict.document?.reduced !== verdict.document?.originalHead,
    verdictRun,
    'keep the two chain heads apart, which is the finding a merged number loses',
  );
  say(`verify-handover ${testCase.document}: exit 0, read by verifyRedaction as ashaveri/redaction, survivors ${survivors}`);

  const missingRun = runBundle(workDir, ['verify-handover', `${testCase.document}.cbor`, `--key=${testCase.key}`, '--json']);
  expect(missingRun.status === 1, missingRun, 'refuse the same amendment with its pack left at home');
  const missing = reportOf(missingRun);
  expect(missing.ok === false, missingRun, 'report an amendment without its pack as a refusal');
  expect(missing.code === 'REDACTION_PACK_UNAVAILABLE', missingRun, `refuse with the missing-pack code, gave ${String(missing.code)}`);
  say(`verify-handover ${testCase.document} without its pack: exit 1, refused ${String(missing.code)}`);

  const wrongRun = runBundle(workDir, ['verify-pack', `${testCase.document}.cbor`, `--key=${testCase.key}`, '--json']);
  expect(wrongRun.status === 1, wrongRun, 'refuse the amendment document handed to the pack verb');
  const wrong = reportOf(wrongRun);
  expect(wrong.ok === false, wrongRun, 'report an amendment as a refusal for this verb');
  expect(wrong.contentType === undefined, wrongRun, 'stop before deciding which type the bytes are');
  expect(wrong.code === 'BAD_PROTECTED_HEADER', wrongRun, `refuse with the header code, gave ${String(wrong.code)}`);
  expect(wrong.message?.includes('typ=ashaveri/redaction') === true, wrongRun, 'name the type it found in the refusal');
  say(`verify-pack ${testCase.document}: exit 1, refused ${String(wrong.code)} naming typ=ashaveri/redaction`);

  const packRun = runBundle(workDir, [
    'verify-handover',
    `${testCase.pack}.cbor`,
    `--key=${testCase.key}`,
    `--companion=${join(workDir, `${testCase.document}.cbor`)}`,
    '--json',
  ]);
  expect(packRun.status === 0, packRun, 'read the pack an amendment speaks about as the pack it is');
  const pack = reportOf(packRun);
  expect(pack.ok === true, packRun, 'report the pack it read as whole');
  expect(pack.contentType === 'ashaveri/pack', packRun, 'answer with the type the document carries and not the one beside it');
  expect(pack.reader === 'verifyPack', packRun, 'say which reader answered');
  say(`verify-handover ${testCase.pack}: exit 0, read by verifyPack as ashaveri/pack with an amendment in the companion position`);
}

/** The identity a TCB info document covers and the run asks by, as Intel's own documents spell both. */
const FMSPC = '00906e1b0d00';
const ISSUE_DATE = '2025-01-01T00:00:00Z';
const NEXT_UPDATE = '2027-01-01T00:00:00Z';
const TCB_DATE = '2025-06-01T00:00:00Z';
const LEVEL = `tcb-date=${TCB_DATE}`;

/** The window the document below signs, in the seconds the machine shape prints it in. */
const WINDOW_FROM = Math.floor(Date.parse(ISSUE_DATE) / 1000);
const WINDOW_UNTIL = Math.floor(Date.parse(NEXT_UPDATE) / 1000);

/** The instant the naming record is chained at, which is both the held instant and the moment weighed. */
const CARRIED_IAT = 1_750_000_000;

/** The three names this proof gives the container it builds, in the directory it builds the run in. */
const HONEST_PACK = 'carried-tcb-info.cbor';
const WITHHELD_PACK = 'carried-tcb-info-object-withheld.cbor';
const ROOT_FILE = 'intel-root.der';

/** One held slot's row of a report, read out of the document by the digest that keys it. */
function carriedRowOf(run: BundleRun, digest: string): CarriedRow {
  const row = (reportOf(run).document ?? {}) as Record<string, unknown>;
  const found = row[`carried-${digest}`];
  if (found === undefined) {
    throw new Error(`the report printed no carried row keyed 'carried-${digest}'\n${describeRun(run)}`);
  }
  return found as CarriedRow;
}

/** The row stating the roots an appraisal was weighed under, refused by name where a report has none. */
function rootsRowOf(run: BundleRun): CollateralRootsRow {
  const roots = reportOf(run).document?.collateralRoots;
  if (roots === undefined) {
    throw new Error(`the report printed no 'collateralRoots' row, so the roots this run stood behind are unstated\n${describeRun(run)}`);
  }
  return roots;
}

/**
 * The material a pack carries, weighed by the artifact in a directory that holds no checkout.
 *
 * Three runs, and the one variable each moves: the honest container weighed under a named root and a named
 * question, the same container with the object one held slot names taken out of the carried list, and the
 * honest container again with the question asked but no root named. The first is the half this proof existed
 * to cover and the second is the reason it is a proof rather than a demonstration, because a weighing that
 * ran over whatever a document claimed would answer the same question a pack stating more than it holds
 * cannot be refused for. The third is what makes the root rule observable: an appraisal that had inherited
 * the roots bundled with the verifier would have read the bytes and answered with a state about them, and
 * what it answers instead is the refusal that names the field this run left empty.
 *
 * `verify-pack` carries the first and the third because a step that knows it is reading a pack is the step
 * this path is built for, and `verify-handover` carries the refusal because the free verb is the one a
 * reader of a pile reaches for, and both verbs weigh through the same rows.
 */
function proveCarried(workDir: string): void {
  // A vendor generated here, and a document signed by it, so the only signature this run believes is the one
  // it pinned: nothing published by a real vendor is reached, asserted about, or needed for the reading to hold.
  const vendor = testVendor({
    notBefore: secondsOf('2020-01-01T00:00:00.000Z'),
    notAfter: secondsOf('2035-01-01T00:00:00.000Z'),
  });
  const tcbDocument = signedDocument(
    tcbInfo({
      fmspc: FMSPC,
      issueDate: ISSUE_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: TCB_DATE, tcbStatus: 'UpToDate' }],
    }),
    vendor,
  );
  const validityContext = new TextEncoder().encode('the validity window the appraisal above was published in');
  const digestOfTcb = digestHexOf(tcbDocument);
  const digestOfContext = digestHexOf(validityContext);

  // One record whose two anchor slots both state a digest, so the held half of the path is what runs.
  const entries: readonly PackEntry[] = [{
    id: 'receipt-0',
    iat: CARRIED_IAT,
    receipt: anchorReceiptOf({ col: held(tcbDocument), val: held(validityContext) }, CARRIED_IAT),
  }];

  writeFileSync(join(workDir, HONEST_PACK), packOf(entries, [carriedObject(tcbDocument), carriedObject(validityContext)]));
  // The same record, the same chain and the same key, with the object the `val` slot names left out of the
  // carried list. `signPack` refuses to seal this manifest, exactly as it refuses the published fault rows,
  // which is why the piecewise writer is the one that reaches it: nothing here hands the reader a document no
  // deployment could have assembled, and nothing here hands it one the format would have accepted either.
  writeFileSync(join(workDir, WITHHELD_PACK), sealCarriedPack(packManifestOf(entries, [carriedObject(tcbDocument)])));
  const rootPath = join(workDir, ROOT_FILE);
  writeFileSync(rootPath, vendor.rootDer);

  const keyFlag = `--key=${RECEIPT_PUBLIC_B64URL}`;
  const questionArgs = [
    '--collateral-origin=col=intel-tcb-info',
    '--collateral-platform=col=tdx',
    `--collateral-cpu-type=col=${FMSPC}`,
    `--collateral-level=col=${LEVEL}`,
  ];
  const rootArgs = [`--intel-root=${rootPath}`];

  const weighedRun = runBundle(workDir, ['verify-pack', HONEST_PACK, keyFlag, ...rootArgs, ...questionArgs, '--json']);
  expect(weighedRun.status === 0, weighedRun, 'accept the pack whose held slots name the material it carries');
  const weighed = reportOf(weighedRun);
  expect(weighed.ok === true, weighedRun, 'report the carried pack as a document it read');
  expect(weighed.contentType === 'ashaveri/pack', weighedRun, 'name the content type the report is about');
  expect(weighed.reader === 'verifyPack', weighedRun, 'say which reader answered');

  const roots = rootsRowOf(weighedRun);
  expect(roots.handed === 1 && roots.files[0] === rootPath, weighedRun, `state the one root this run named, saw ${JSON.stringify(roots.files)}`);
  expect(roots.bundledConsulted === false, weighedRun, 'state that no root bundled with the artifact was consulted');
  expect(
    roots.rule.includes('no root bundled with the verifier is consulted on this path'),
    weighedRun,
    'state the root rule the row prints beside the answer',
  );

  const col = carriedRowOf(weighedRun, digestOfTcb);
  expect(col.item === 'receipt-0' && col.slot === 'col', weighedRun, 'name the record and the slot that asked about these bytes');
  expect(
    col.namedBy.length === 1 && col.namedBy[0]?.item === 'receipt-0' && col.namedBy[0]?.slot === 'col',
    weighedRun,
    `name every held slot stating this digest, saw ${JSON.stringify(col.namedBy)}`,
  );
  expect(col.carried === true && col.carriedBytes === tcbDocument.byteLength, weighedRun, 'report the bytes the pack holds for that digest');
  expect(
    col.appraisalAt === CARRIED_IAT && col.heldAt === CARRIED_IAT,
    weighedRun,
    'read the answer at the stamp the naming record was chained at, and at no instant this run minted',
  );
  expect(
    col.environment === PUBLISHED_PAYLOAD.meas.tee,
    weighedRun,
    `print the environment kind the naming receipt states for its own measurement, saw ${col.environment}`,
  );
  expect(
    col.question?.origin === 'intel-tcb-info' && col.question.platform === 'tdx' && col.question.cpuType === FMSPC
      && col.question.level === LEVEL && col.question.roots === 1,
    weighedRun,
    `echo the question as this run spelled it, saw ${JSON.stringify(col.question)}`,
  );
  expect(col.weighed === true && col.notWeighed === null, weighedRun, 'report the slot as weighed rather than as unasked');
  expect(col.state === 'stale' && col.reach === 'historical-knowledge', weighedRun, `answer stale and historical, saw ${String(col.state)} / ${String(col.reach)}`);
  expect(col.readAs === 'trusted' && col.vendorStatus === 'UpToDate', weighedRun, `print what the vendor's own words say, saw ${String(col.readAs)} / ${String(col.vendorStatus)}`);
  expect(col.declaredCpuType === FMSPC, weighedRun, 'print the identity the document declares for itself beside the one asked');
  expect(col.anchorDigest === vendor.rootDigest, weighedRun, `reach the anchor this run pinned and no other, saw ${String(col.anchorDigest)}`);
  expect(
    col.window?.from === WINDOW_FROM && col.window?.until === WINDOW_UNTIL && col.retainUntil === WINDOW_UNTIL,
    weighedRun,
    `print the window the vendor signed beside the instant it was read against, saw ${JSON.stringify(col.window)}`,
  );
  expect(
    col.refusal?.code === 'COLLATERAL_NOT_OBSERVED' && col.refusal.missing.includes('retained'),
    weighedRun,
    `carry the appraisal's own refusal, saw ${JSON.stringify(col.refusal)}`,
  );
  // The half an exit code cannot state on its own: a weighing that reads the material as stale, historical
  // and owed a field this run did not supply leaves the verdict the seal gave the container exactly where it
  // found it, and the report prints both numbers rather than merging them into one.
  expect(weighed.ok === true && weighedRun.status === 0, weighedRun, 'leave the exit code to the seal while an appraisal refuses');

  const val = carriedRowOf(weighedRun, digestOfContext);
  expect(
    val.weighed === false && val.state === null && val.question === null && String(val.notWeighed).includes("'val'"),
    weighedRun,
    `report the slot no flag named as not weighed with the reason, saw ${String(val.notWeighed)}`,
  );
  say(
    `verify-pack ${HONEST_PACK}: exit 0, held col of receipt-0 resolved to ${String(tcbDocument.byteLength)} carried bytes at digest ${digestOfTcb}, ` +
      `weighed as ${col.state}/${String(col.reach)} reading ${String(col.readAs)} ${String(col.vendorStatus)} under the pinned anchor ${String(col.anchorDigest)}, ` +
      `window ${String(WINDOW_FROM)}..${String(WINDOW_UNTIL)} read against ${String(CARRIED_IAT)}, refusal ${String(col.refusal?.code)} moved nothing`,
  );

  const withheldRun = runBundle(workDir, ['verify-handover', WITHHELD_PACK, keyFlag, ...rootArgs, ...questionArgs, '--json']);
  expect(withheldRun.status === 1, withheldRun, 'refuse the pack that names a held digest it carries no object for');
  const withheld = reportOf(withheldRun);
  expect(withheld.ok === false, withheldRun, 'report the short carried list as a refusal');
  expect(withheld.contentType === 'ashaveri/pack', withheldRun, 'name the type of the document it refused');
  expect(withheld.code === 'PACK_CARRIED_UNRESOLVED', withheldRun, `refuse with the unresolved-carried code, gave ${String(withheld.code)}`);
  expect(
    withheld.message?.includes(`receipt-0 states a held val digest ${digestOfContext} this pack carries no object for`) === true,
    withheldRun,
    'name the record, the slot and the digest the container left unanswered',
  );
  say(
    `verify-handover ${WITHHELD_PACK}: exit 1, refused ${String(withheld.code)} at receipt-0's held val digest ${digestOfContext}, ` +
      'which is the weighing answering for a container the format accepted and not for what a document claims to hold',
  );

  const unpinnedRun = runBundle(workDir, ['verify-pack', HONEST_PACK, keyFlag, ...questionArgs, '--json']);
  expect(unpinnedRun.status === 0, unpinnedRun, 'still accept the pack when the question is asked under no root');
  const unpinned = reportOf(unpinnedRun);
  expect(unpinned.ok === true, unpinnedRun, 'report the pack as read, which is the container question and not the appraisal one');
  expect(rootsRowOf(unpinnedRun).handed === 0, unpinnedRun, 'state that no root was handed to this run');
  expect(
    rootsRowOf(unpinnedRun).rule.includes('no root bundled with the verifier was consulted either'),
    unpinnedRun,
    'state that nothing bundled was consulted in the absence of a named root',
  );
  const unpinnedCol = carriedRowOf(unpinnedRun, digestOfTcb);
  expect(
    unpinnedCol.state === 'missing-context' && unpinnedCol.refusal?.code === 'COLLATERAL_ANCHOR_NOT_PINNED'
      && unpinnedCol.refusal.missing.includes('roots'),
    unpinnedRun,
    `answer with the refusal that names the field left empty, saw ${JSON.stringify(unpinnedCol.refusal)}`,
  );
  expect(
    unpinnedCol.readAs === null && unpinnedCol.window === null && unpinnedCol.anchorDigest === null,
    unpinnedRun,
    'print no reading, no window and no anchor for bytes nothing pinned a root for',
  );
  say(
    `verify-pack ${HONEST_PACK} under no --intel-root: exit 0, refused ${String(unpinnedCol.refusal?.code)} naming roots, ` +
      'read as no state about the vendor, which is the answer an appraisal that had consulted a bundled root would not give',
  );
  say(
    'the bundle answered three runs over a container built here: one held slot resolved to the vendor-signed bytes the pack carries and weighed under the root this run named, ' +
      'one refusal of the same pack with the object a held slot names left out of its carried list, and the same weighing asked again under no root and answered by the refusal naming the field it left empty',
  );
}

function main(): void {
  const [workDir, dataDir] = process.argv.slice(2);
  if (workDir === undefined || dataDir === undefined) {
    throw new Error('usage: offline-proof <work-directory> <fixtures-data-directory>');
  }
  // The first argument is read two ways at once: the paths this proof writes are built out of it here, and
  // it is handed to each run of the artifact as that run's own working directory. A relative one is then
  // resolved twice over, once from where this script was started and again from where the child already
  // is, and what the second reading reaches is the directory inside itself: a run refused with `ENOENT` on
  // a file this proof wrote one step earlier, in a path that names nothing on any disk. Refusing the shape
  // at the entry point is what makes the sentence the reader gets one about the argument. The fixtures
  // directory is only ever read by this process, so its own spelling stays as it is.
  if (!isAbsolute(workDir)) {
    throw new Error(
      `usage: offline-proof <absolute-work-directory> <fixtures-data-directory>, and '${workDir}' is a relative path: ` +
        'the work directory is both the paths below are built out of and the working directory each run of the artifact starts in, ' +
        'so it has to name one place wherever this script is started from',
    );
  }

  const key = JSON.parse(readFileSync(join(dataDir, 'keys/receipt-key-v1.json'), 'utf8')) as FixtureKey;
  const { payload } = JSON.parse(
    readFileSync(join(dataDir, 'receipts/receipt-valid-v1.json'), 'utf8'),
  ) as FixtureReceipt;
  const publicKey = publicKeyFromHex(key.publicKey);

  writeFileSync(
    join(workDir, 'manifest.json'),
    JSON.stringify({
      v: 1,
      iss: payload.iss,
      ins: payload.ins,
      epk: payload.epk,
      keys: [{ kid: key.kid, alg: 'Ed25519', publicKey }],
      models: [{ id: payload.mdl, wts: payload.wts }],
      meas: { tee: payload.meas.tee, m: payload.meas.m },
    }),
  );

  writeFileSync(
    join(workDir, 'policy.json'),
    JSON.stringify({
      v: 1,
      issuers: [payload.iss],
      instances: [payload.ins],
      keys: { [key.kid]: publicKey },
      measurements: { [payload.meas.tee]: [payload.meas.m] },
      maxReceiptAgeSeconds: 300,
      maxEvidenceAgeSeconds: 900,
    }),
  );

  // Sourced by the job so the verifier is handed the four values it needs. A receipt is checked against
  // the time it names, so a step that used the current clock would fail a valid vector.
  writeFileSync(
    join(workDir, 'args.env'),
    `NONCE=${payload.nce}\nREQ=${payload.req}\nRES=${payload.res}\nNOW=${new Date(payload.iat * 1000).toISOString()}\n`,
  );

  say(`wrote manifest.json, policy.json and args.env into ${workDir}`);
  proveHandoverVerbs(workDir, dataDir);
  proveCarried(workDir);
}

/**
 * The three verbs that read a whole signed document, run over the published pack, export and amendment
 * through the built artifact.
 *
 * The documents are the vectors' own bytes under the names their rows carry, and the keys are the ones
 * those rows say a caller holds, so what is asserted is an answer about published material rather than
 * about a file assembled to agree with the reader. The bundle is copied in beside them and run from that
 * directory, which is the one arrangement that shows the artifact carries these verbs with it: an import
 * the bundler left unresolved would fail here, in the shape it fails on a machine with no checkout, no
 * install and nothing to fetch.
 */
function proveHandoverVerbs(workDir: string, dataDir: string): void {
  try {
    copyFileSync(BUNDLE_SOURCE, join(workDir, BUNDLE_NAME));
  } catch (err) {
    throw new Error(
      `this proof runs a built artifact and does not build one: ${BUNDLE_SOURCE} is not there (${err instanceof Error ? err.message : String(err)}). ` +
        "Run 'pnpm build' and 'pnpm -C packages/cli bundle' from the repository root first",
    );
  }

  const packRows = (JSON.parse(readFileSync(join(dataDir, 'pack-v1.json'), 'utf8')) as PackVectorFile).vectors;
  const exportFile = JSON.parse(readFileSync(join(dataDir, 'export-v1.json'), 'utf8')) as ExportVectorFile;
  const whole = rowNamed('pack-v1.json', packRows, 'well-formed-three-items');
  const edited = rowNamed('pack-v1.json', packRows, 'receipt-byte-changed-after-sealing');
  const exportRow = rowNamed('export-v1.json', exportFile.vectors, 'companion-handed-and-checked');
  const packKey = whole.read.pinned;
  if (packKey === undefined) {
    throw new Error('the published pack row states no pinned key, so the run would designate one the document does not name');
  }
  const walked = whole.walk;
  if (walked === undefined) {
    throw new Error(`the published pack row '${whole.name}' states no walk, so there is no order to compare the reading against`);
  }
  const companion = exportRow.read.companions?.[0];
  if (companion === undefined) {
    throw new Error('the published export row states no companion file, so there is no original for the reading to run over');
  }

  const originalBytes = Buffer.from(companion.bytesBase64Url, 'base64url');
  writeFileSync(join(workDir, companion.name), originalBytes);
  for (const row of [whole, edited, exportRow]) {
    writeFileSync(join(workDir, `${row.name}.cbor`), Buffer.from(row.documentBase64Url, 'base64url'));
  }

  const redactionRows = (JSON.parse(readFileSync(join(dataDir, 'redaction-v1.json'), 'utf8')) as RedactionVectorFile).vectors;
  const amendment = rowNamed('redaction-v1.json', redactionRows, 'removed-middle-record');
  const amendmentKey = amendment.read.pinned;
  if (amendmentKey === undefined) {
    throw new Error('the published redaction row states no pinned key, so the run would designate one the document does not name');
  }
  const amendmentPack = stated(amendment.packBase64Url, 'pack the amendment designates');
  // The published pair is sealed by one key and speaks about the pack the pack suite already publishes, so
  // the amendment below is read against the same bytes the pack verb reads rather than a second copy of a
  // pack this file assembled.
  if (amendmentPack !== whole.documentBase64Url) {
    throw new Error(
      `the published amendment designates a pack other than the row '${whole.name}' publishes, so the two readings below would not be about one document`,
    );
  }
  writeFileSync(join(workDir, `${amendment.name}.cbor`), Buffer.from(amendment.documentBase64Url, 'base64url'));

  provePack(workDir, {
    whole: whole.name,
    edited: edited.name,
    wrongType: exportRow.name,
    key: packKey,
    otherKey: publicKeyFromHex(exportFile.layout.key.publicKeyHex),
    walked,
  });
  proveExport(workDir, {
    document: exportRow.name,
    wrongType: whole.name,
    key: publicKeyFromHex(exportFile.layout.key.publicKeyHex),
    otherKey: packKey,
    companion: companion.name,
    digest: createHash('sha256').update(originalBytes).digest('hex'),
  });
  proveRedaction(workDir, {
    document: amendment.name,
    pack: whole.name,
    key: amendmentKey,
    packDigest: createHash('sha256').update(Buffer.from(amendmentPack, 'base64url')).digest('hex'),
    survivors: stated(amendment.survivors, 'survivor run'),
    reduced: stated(amendment.reducedHex, 'chain head over the survivors'),
    originalHead: stated(amendment.originalHeadHex, 'head the pack itself carries'),
  });

  say(
    'the bundle answered ten runs over the published pack, export and amendment: two readings and a survivor run, one refusal of the wrong type for each verb, one refusal of a document whose own contents do not hold for each verb, and one refusal of an amendment handed without the pack it designates',
  );
}

main();
