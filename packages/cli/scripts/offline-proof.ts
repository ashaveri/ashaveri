import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The inputs the single-file verifier is proved against, written into a directory that holds nothing
 * else, and the two verbs proved by running the artifact over the published pack and export.
 *
 * The CI job that runs the bundle needs a policy and a deployment manifest whose pins match the committed
 * receipt it is about to check, and this started life as a script pasted into the workflow file. That shape
 * is the reason it is a file now: a heredoc inside a job is read by no `tsconfig`, so a wrong field name in
 * it fails on a runner, in a pull request, with nothing local able to reach it first. As a script it is
 * typechecked with the rest of this package and runnable by hand, which is the only way the bundle's proof
 * can be observed anywhere other than Actions.
 *
 * The pack and the export are proved here for that same reason, and they are proved by running: the job
 * reaches this file with one line, so a verb added to the bundle is only covered once something in here
 * starts a process with it. `verify-pack` and `verify-export` are the same reader over the same bytes as
 * `verify-handover` with one answer pinned, and a claim that a stranger can verify a pack with nothing
 * installed is about those two verbs as much as about the receipt. So each is run three times: over its
 * own document, over the other verb's, and over one where the material beside the document does not
 * answer for it.
 *
 * Nothing is invented here. Every value is read out of the committed vector, so the generated document
 * cannot state a pin the receipt does not carry, and the verification time is the vector's own `iat`
 * rather than the wall clock, because this is not re-issuing a receipt. Each assertion below is read out
 * of the report the artifact printed rather than out of its exit status, because a status says that a
 * command stopped and only the report says which document it stopped about and what it found.
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

function rowNamed(file: string, vectors: readonly VectorRow[], name: string): VectorRow {
  const row = vectors.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published ${file} has no vector named '${name}', so this proof would be asserting a document nothing publishes`);
  }
  return row;
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
  };
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
 * way it would on a machine that has nothing installed: the directory has the file, the documents and the
 * four inputs, and no `node_modules` above it. A run that needed an installed tree would fail here for
 * the reason it would fail there, which is what makes these six commands the property the job exists to
 * show rather than a restatement of it.
 */
function runBundle(workDir: string, args: readonly string[]): BundleRun {
  const result = spawnSync(process.execPath, [BUNDLE_NAME, ...args], {
    cwd: workDir,
    encoding: 'utf8',
    // The slowest of the six runs below measures 160 ms here, which is three inner receipts verified and
    // one Node start; the ceiling is two hundred times that so a hang on a runner is a failure naming one
    // command rather than a job timeout naming a step.
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

function main(): void {
  const [workDir, dataDir] = process.argv.slice(2);
  if (workDir === undefined || dataDir === undefined) {
    throw new Error('usage: offline-proof <work-directory> <fixtures-data-directory>');
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
  provePinnedVerbs(workDir, dataDir);
}

/**
 * The two pinned verbs, run over the published pack and export through the built artifact.
 *
 * The documents are the vectors' own bytes under the names their rows carry, and the keys are the ones
 * those rows say a caller holds, so what is asserted is an answer about published material rather than
 * about a file assembled to agree with the reader. The bundle is copied in beside them and run from that
 * directory, which is the one arrangement that shows the artifact carries these two verbs with it: an
 * import the bundler left unresolved would fail here, in the shape it fails on a machine with no
 * checkout, no install and nothing to fetch.
 */
function provePinnedVerbs(workDir: string, dataDir: string): void {
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

  say(
    'the bundle answered six runs over the published pack and export: two readings, one refusal of the wrong type for each verb, and one refusal of a document whose own contents do not hold for each verb',
  );
}

main();
