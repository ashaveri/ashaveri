import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import {
  entryPoints,
  isPublishable,
  PACKAGE_SCOPE,
  parseRange,
  rangesAgree,
  scopedManifests,
  type PackageManifest,
} from './doc-contract.js';

/**
 * The published surface, run the way a consumer runs it.
 *
 * `publish-manifests.test.ts` reads the manifests. This file reads what a manifest becomes: it packs every
 * publishable package with the same `pnpm pack` the publish workflow runs, installs the six tarballs into a
 * fresh directory under the system temp path, and then asks questions of the files sitting in that directory.
 * Nothing here imports the workspace. The script that does the verifying is written into the installed tree
 * and run by an absolute path inside it, and the first thing the test asserts about its answer is that every
 * module the script resolved, resolved under that prefix rather than under this checkout. A pass therefore
 * attests to the bytes a stranger receives, which is the only artifact a publish cannot take back.
 *
 * Four things a consumer needs and a workspace link hides are checked here: that `pnpm pack` rewrote every
 * `workspace:` sibling range into a version an installer can act on, since npm implements no such protocol;
 * that the tarball carries the built entry points and the normative CDDL and JSON twins its own `files` list
 * promised; that the six install together as one copy of each package rather than as six trees chasing
 * versions; and that the installed library and the installed command reach the same verdict on the same
 * published receipt, with the refusal the fixtures state on the bytes that were tampered with.
 *
 * What this file cannot check, and says so rather than stubbing it: a third of the row's acceptance belongs
 * to a publish that has not happened. Whether the registry serves these names, whether the provenance
 * attestation a run mints verifies against them, and whether `npm audit` and a consumer's own lockfile accept
 * what lands, all need bytes on a registry. Nothing here reaches one: the pack is local, the install reads the
 * local tarballs, and only the packages' own third-party dependencies come from a cache, or from the registry
 * a developer already installed this workspace through.
 */

/** Repo-relative, because that is the spelling a failure message has to be readable in. */
const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const PACKAGE_PARENT = fileURLToPath(new URL('../../', import.meta.url));
const SCOPE = PACKAGE_SCOPE;
const ROOT_MANIFEST = 'package.json';

/** One pack, one install, and one consumer run, each with room for a cold cache. */
const PACK_CEILING_MS = 180_000;
const INSTALL_CEILING_MS = 600_000;
const NODE_CEILING_MS = 180_000;
const PREP_CEILING_MS = 900_000;

/**
 * The publishable set, walked rather than listed. Which manifest a publish uploads is the rule
 * `doc-contract.ts` states once, the same rule `publish-manifests.test.ts` holds the workspace to and the
 * workflow's order answers to, so a package added under `packages/` arrives here too, and a package whose
 * `private` flag flipped is installed and checked before anything publishes it. This walk stops at
 * `packages/`, because a consumer installs the packages and this file asks questions of those bytes.
 */
function publishableManifests(): PackageManifest[] {
  const dirs = readdirSync(PACKAGE_PARENT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(PACKAGE_PARENT, entry.name))
    .filter((dir) => existsSync(path.join(dir, 'package.json')));
  const found = publishableFrom(
    dirs.map((dir) => ({ dir, text: readFileSync(path.join(dir, 'package.json'), 'utf8') })),
  );
  if (found.length === 0) throw new Error(`no publishable ${SCOPE}* manifest was found under ${PACKAGE_PARENT}`);
  return found;
}

/**
 * The manifests a publish would upload, out of the files one caller read. The `private` marker is asked of
 * each manifest before the shared reader is handed it, because `scopedManifests` refuses a scoped manifest
 * that states no version, and this suite has no use for the version of a package it neither packs nor
 * installs: a private package added under `packages/` without one would arrive as a refusal in every check
 * here, including the ones that never read it. Ordering is the whole of the change. The refusal still
 * reaches anything this set is built to pack, and `publish-manifests.test.ts` holds the whole workspace,
 * gateway included, to one version each.
 */
function publishableFrom(reads: Array<{ dir: string; text: string }>): PackageManifest[] {
  return scopedManifests(reads.filter((one) => isPublishable(JSON.parse(one.text) as Record<string, unknown>)));
}

/** A path spelled with forward slashes, which is how a leaked one reaches a manifest from either side. */
function asUrlPath(value: string): string {
  return value.split('\\').join('/');
}

/**
 * Serialized JSON text with each escaped separator read back as the one character the directory is written
 * with. `JSON.stringify` doubles every separator a native Windows path carries, so a manifest holding
 * `dir\sub` arrives in text as `dir\\sub`, and a comparison that only turns separators into slashes lands on
 * `dir//sub`: a string no needle spells. Forward slashes pass through untouched, so both spellings of one
 * directory come out of here as the same text.
 */
function asUnescapedText(value: string): string {
  return asUrlPath(value.split('\\\\').join('\\'));
}

/** Whether one serialized manifest names one directory, in either spelling its separators arrive in. */
function carriesPath(serialized: string, dir: string): boolean {
  return asUnescapedText(serialized).includes(asUrlPath(dir));
}

interface Run {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * A package manager command. Spawning the named program works wherever the launcher on `PATH` is an
 * executable, which is what a POSIX runner holds. Where it is a `.cmd` shim, which is what a Windows install
 * of npm and pnpm leaves, Node refuses to spawn it without a shell, so the same command is rebuilt as one
 * quoted line and only tokens that a shell could otherwise re-read are refused outright.
 */
function runManager(command: string, args: string[], cwd: string, timeoutMs: number): Run {
  const direct = spawnSync(command, args, { cwd, encoding: 'utf8', timeout: timeoutMs });
  if (direct.error === undefined) return asRun(direct);
  return asRun(spawnSync(shellLine(command, args), { cwd, encoding: 'utf8', shell: true, timeout: timeoutMs }));
}

interface Spawned {
  readonly status: number | null;
  readonly stdout?: string;
  readonly stderr?: string;
  readonly error?: Error;
}

function asRun(result: Spawned): Run {
  if (result.error !== undefined) {
    throw new Error(`the command could not be started at all: ${result.error.message}`);
  }
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** One command word, then its arguments, each quoted or refused. */
function shellLine(command: string, args: string[]): string {
  if (!/^[a-z][a-z0-9-]*$/u.test(command)) {
    throw new Error(`${command} is not a command word this test will build a shell line from`);
  }
  const quote = (token: string): string => {
    if (process.platform === 'win32') {
      if (/["%`$^|&<>]/u.test(token)) {
        throw new Error(`${token} carries a character a cmd.exe line cannot carry inside quotes`);
      }
      return /\s/u.test(token) ? `"${token}"` : token;
    }
    if (/[\0`$|&<>\n]/u.test(token)) {
      throw new Error(`${token} carries a character a /bin/sh line cannot be quoted to hold`);
    }
    return `'${token.replace(/'/gu, "'\\''")}'`;
  };
  return [command, ...args].map(quote).join(' ');
}

function runNode(script: string, args: string[], cwd: string): Run {
  return asRun(spawnSync(process.execPath, [script, ...args], { cwd, encoding: 'utf8', timeout: NODE_CEILING_MS }));
}

interface PackedPackage {
  readonly name: string;
  readonly tarball: string;
  readonly manifest: Record<string, unknown>;
  readonly members: Map<string, number>;
}

interface TarMember {
  readonly size: number;
  readonly text: string;
}

/**
 * The members of one packed tarball, read out of the gzip stream without an external binary. Names come from
 * the ustar header, with the GNU long-name block and the ustar prefix field both honoured, because a tarball
 * is exactly what a consumer is served and a check that read only the extracted copy would be a check of the
 * installer rather than of the artifact.
 */
function unpack(tarball: string): Map<string, TarMember> {
  const bytes = gunzipSync(readFileSync(tarball));
  const field = (at: number, length: number): string => {
    const nul = bytes.indexOf(0, at);
    const stop = nul < 0 || nul > at + length ? at + length : nul;
    return bytes.subarray(at, stop).toString('utf8').trim();
  };
  const members = new Map<string, TarMember>();
  let offset = 0;
  let pendingLongName = '';
  while (offset + 512 <= bytes.length) {
    const header = offset;
    offset += 512;
    if (bytes.subarray(header, header + 512).every((byte) => byte === 0)) continue;
    const sizeField = field(header + 124, 12);
    const size = Number.parseInt(sizeField.length > 0 ? sizeField : '0', 8);
    const typeflag = String.fromCharCode(bytes[header + 156] ?? 0);
    const raw = field(header, 100);
    const prefix = field(header + 345, 155);
    const payload = bytes.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;
    if (typeflag === 'L') {
      pendingLongName = payload.toString('utf8').replace(/\0+$/u, '');
      continue;
    }
    const name = pendingLongName.length > 0 ? pendingLongName : prefix.length > 0 ? `${prefix}/${raw}` : raw;
    pendingLongName = '';
    if (typeflag === '0' || typeflag === '\0') members.set(name, { size, text: payload.toString('utf8') });
  }
  return members;
}

function readTarball(tarball: string): PackedPackage {
  const members = unpack(tarball);
  const manifestMember = 'package/package.json';
  const manifestText = members.get(manifestMember)?.text;
  if (manifestText === undefined) throw new Error(`${path.basename(tarball)} ships no manifest at ${manifestMember}`);
  const manifest = JSON.parse(manifestText) as Record<string, unknown>;
  const name = manifest['name'];
  if (typeof name !== 'string') throw new Error(`${tarball} ships a manifest naming nothing`);
  return { name, tarball, manifest, members: new Map([...members].map(([key, value]) => [key, value.size])) };
}

/** The consumer's own script, written into the installed tree and run from it. */
const CONSUMER_SCRIPT = `import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const requireFrom = createRequire(import.meta.url);
const prefix = path.dirname(fileURLToPath(import.meta.url));
const receipt = await import('@ashaveri/receipt');
const fixtures = await import('@ashaveri/fixtures');
const sdk = await import('@ashaveri/sdk');
const attest = await import('@ashaveri/attest-core');
const collateral = await import('@ashaveri/collateral');

const manifest = fixtures.loadManifest();
const key = fixtures.loadFixtureKey();
const accepted = (wanted) => manifest.fixtures.find((row) => row.v === wanted && row.expected === 'verify-ok');
// The row this file hands over as tampered is found by the name the fixture publishes it under, and not by
// the code its row states: a row chosen because of the answer it expects cannot then be the source of that
// answer. The stated code travels into the report from the row, so both refusal checks compare the reader
// with the fixture rather than with a value restated on either side of the installed boundary.
const tampered = manifest.fixtures.find((row) => row.name === 'receipt-tampered-v1');

const report = {
  resolved: {
    '@ashaveri/receipt': requireFrom.resolve('@ashaveri/receipt'),
    '@ashaveri/fixtures': requireFrom.resolve('@ashaveri/fixtures'),
    '@ashaveri/sdk': requireFrom.resolve('@ashaveri/sdk'),
    '@ashaveri/attest-core': requireFrom.resolve('@ashaveri/attest-core'),
    '@ashaveri/collateral': requireFrom.resolve('@ashaveri/collateral'),
  },
  exportCount: {
    '@ashaveri/receipt': Object.keys(receipt).length,
    '@ashaveri/fixtures': Object.keys(fixtures).length,
    '@ashaveri/sdk': Object.keys(sdk).length,
    '@ashaveri/attest-core': Object.keys(attest).length,
    '@ashaveri/collateral': Object.keys(collateral).length,
  },
  sdkSurface: { client: typeof sdk.AshaveriClient, wrap: typeof sdk.wrapOpenAI },
  rows: manifest.fixtures.length,
  verified: {},
  tamperedRow: '',
  tamperedStated: '',
  tampered: '',
  keyBase64Url: receipt.toBase64Url(key.publicKey),
  prefix: prefix,
};

const v1 = accepted(1);
const v2 = accepted(2);
if (v1 === undefined || v2 === undefined) {
  throw new Error('the published manifest states no accepted row to read');
}
if (tampered === undefined) {
  throw new Error('the published manifest states no receipt-tampered-v1 row, so nothing here is tampered');
}
report.tamperedRow = tampered.name;
report.tamperedStated = tampered.expected;
for (const row of [v1, v2]) {
  const bytes = fixtures.loadReceiptFixture(row.name).bytes;
  const iat = receipt.decodeReceipt(bytes).payload.iat;
  const verified = receipt.verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: iat });
  report.verified['v' + String(row.v)] = { name: row.name, payloadVersion: verified.payload.v, model: verified.payload.mdl };
}
writeFileSync(path.join(prefix, 'installed-accepted.cbor'), Buffer.from(fixtures.loadReceiptFixture(v1.name).bytes));
writeFileSync(path.join(prefix, 'installed-tampered.cbor'), Buffer.from(fixtures.loadReceiptFixture(tampered.name).bytes));
try {
  const bytes = fixtures.loadReceiptFixture(tampered.name).bytes;
  receipt.verifyReceipt(bytes, { publicKey: key.publicKey, nowSeconds: receipt.decodeReceipt(bytes).payload.iat });
  report.tampered = 'accepted';
} catch (error) {
  report.tampered = String(error.code);
}

process.stdout.write(JSON.stringify(report));
`;

interface ConsumerReport {
  readonly resolved: Record<string, string>;
  readonly exportCount: Record<string, number>;
  readonly sdkSurface: { readonly client: string; readonly wrap: string };
  readonly rows: number;
  readonly verified: Record<string, { name: string; payloadVersion: number; model: string }>;
  readonly tamperedRow: string;
  readonly tamperedStated: string;
  readonly tampered: string;
  readonly keyBase64Url: string;
  readonly prefix: string;
}

let scratch = '';
let prefix = '';
let packed: PackedPackage[] = [];
let consumer: ConsumerReport | null = null;

beforeAll(() => {
  scratch = mkdtempSync(path.join(tmpdir(), 'ashaveri-packed-'));
  prefix = mkdtempSync(path.join(tmpdir(), 'ashaveri-consumer-'));
  const targets = publishableManifests();
  for (const target of targets) {
    const result = runManager('pnpm', ['-C', target.dir, 'pack', '--pack-destination', scratch], REPO_ROOT, PACK_CEILING_MS);
    expect(result.status, `pnpm pack of ${target.name} failed: ${result.stderr.slice(0, 400)}`).toBe(0);
  }
  const tarballs = readdirSync(scratch)
    .filter((entry) => entry.endsWith('.tgz'))
    .map((entry) => path.join(scratch, entry));
  expect(tarballs.length, `the six publishable manifests packed into ${tarballs.length} tarballs`).toBe(targets.length);
  packed = tarballs.map(readTarball).sort((a, b) => a.name.localeCompare(b.name));

  writeFileSync(
    path.join(prefix, 'package.json'),
    `${JSON.stringify({ name: 'installed-surface-check', private: true, version: '0.0.0' }, null, 2)}\n`,
  );
  const installed = runManager('npm', ['install', '--no-audit', '--no-fund', '--prefer-offline', '--loglevel', 'error', ...tarballs], prefix, INSTALL_CEILING_MS);
  expect(installed.status, `installing the packed tarballs failed: ${installed.stderr.slice(0, 600)}`).toBe(0);

  writeFileSync(path.join(prefix, 'consumer-check.mjs'), CONSUMER_SCRIPT);
  const check = runNode(path.join(prefix, 'consumer-check.mjs'), [], prefix);
  expect(check.status, `the consumer script failed: ${check.stderr.slice(0, 600)}`).toBe(0);
  consumer = JSON.parse(check.stdout) as ConsumerReport;
}, PREP_CEILING_MS);

afterAll(() => {
  for (const dir of [scratch, prefix]) {
    if (dir.length > 0) rmSync(dir, { recursive: true, force: true });
  }
});

/** One installed package, read the way the installer left it. */
function installedManifest(name: string): Record<string, unknown> {
  const file = path.join(prefix, 'node_modules', ...name.split('/'), 'package.json');
  return JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
}

function packedOf(name: string): PackedPackage {
  const one = packed.find((candidate) => candidate.name === name);
  if (one === undefined) throw new Error(`${name} was never packed, so this file has nothing to read`);
  return one;
}

describe('the set a publish would upload', () => {
  it('drops a private manifest that states no version before the reader is asked for one', () => {
    // Nothing files a tarball for a package a publish holds back, so its version is no consumer's business,
    // and this suite neither packs nor installs it. Asked in the other order, the shared reader refuses that
    // manifest and the whole run stops: an unrelated package added later, in a shape no publish reads, would
    // arrive here as errors on checks that never opened its directory.
    const reads = [
      { dir: 'packages/kept-public', text: JSON.stringify({ name: '@ashaveri/kept-public', version: '0.1.0' }) },
      { dir: 'packages/kept-private', text: JSON.stringify({ name: '@ashaveri/kept-private', private: true }) },
    ];
    const kept = publishableFrom(reads).map((one) => one.name);
    expect(kept, `the set a publish uploads came out as ${kept.join(', ')}`).toEqual(['@ashaveri/kept-public']);
  });

  it('still refuses a manifest it would pack that states no version', () => {
    // The ordering above is not a tolerance. A manifest this set is built to pack still reaches the one
    // refusal `doc-contract.ts` states, naming its own directory, rather than arriving as an undefined
    // version handed to a pack command.
    const reads = [{ dir: 'packages/kept-public', text: JSON.stringify({ name: '@ashaveri/kept-public' }) }];
    expect(
      () => publishableFrom(reads),
      'a manifest the publish would upload stated no version and the run was allowed to continue',
    ).toThrow('packages/kept-public/package.json names @ashaveri/kept-public');
  });
});

describe('the tarballs a publish would upload', () => {
  it('packs one artifact for every manifest the workspace publishes', () => {
    const names = packed.map((one) => one.name);
    expect(names).toEqual(publishableManifests().map((one) => one.name));
    for (const one of packed) {
      expect(existsSync(one.tarball), `${one.name} was packed to a path that holds nothing`).toBe(true);
      expect(one.members.size, `${one.tarball} holds no members, so the build ran nowhere`).toBeGreaterThan(1);
    }
  });

  it('leaves no workspace range for an installer that implements no such protocol', () => {
    const offenders: string[] = [];
    for (const one of packed) {
      const raw = JSON.stringify(one.manifest);
      if (raw.includes('workspace:')) offenders.push(`${one.name} still spells a range with the workspace protocol`);
      const dependencies = one.manifest['dependencies'];
      if (typeof dependencies !== 'object' || dependencies === null) continue;
      for (const [sibling, range] of Object.entries(dependencies as Record<string, unknown>)) {
        if (!sibling.startsWith(SCOPE)) continue;
        const stated = packedOf(sibling).manifest['version'];
        if (range !== stated) {
          offenders.push(`${one.name} asks for ${sibling} at ${String(range)}, where the packed sibling is ${String(stated)}`);
        }
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('holds inside each tarball every entry point and promised directory its manifest names', () => {
    const missing: string[] = [];
    for (const one of packed) {
      const root = 'package';
      for (const target of entryPoints(one.manifest)) {
        const member = `${root}/${target.replace(/^\.\//u, '')}`;
        if (!one.members.has(member)) missing.push(`${one.name}: ${member}`);
      }
      const files = one.manifest['files'];
      if (!Array.isArray(files) || files.length === 0) throw new Error(`${one.name} ships no files list to check`);
      for (const entry of files) {
        const clean = String(entry).replace(/^\.\//u, '').replace(/\/$/u, '');
        const inside = [...one.members.keys()].some((member) => member === `${root}/${clean}` || member.startsWith(`${root}/${clean}/`));
        if (!inside) missing.push(`${one.name}: ${clean} is promised by files and absent from the tarball`);
      }
    }
    expect(missing.length, `a consumer would be handed a manifest pointing at bytes nobody packed:\n${missing.join('\n')}`).toBe(0);
  });

  it('carries the engines floor into the artifact, where a consumer reads it', () => {
    const root = JSON.parse(readFileSync(path.join(REPO_ROOT, ROOT_MANIFEST), 'utf8')) as {
      engines?: { node?: string };
    };
    const wanted = root.engines?.node;
    if (typeof wanted !== 'string' || wanted.trim().length === 0) {
      throw new Error(`${ROOT_MANIFEST} declares no engines.node, so a packed manifest has no floor to carry`);
    }
    const declared = parseRange(wanted, `${ROOT_MANIFEST} engines.node`);
    const disagreed: string[] = [];
    for (const one of packed) {
      const engines = one.manifest['engines'];
      const stated =
        typeof engines === 'object' && engines !== null ? (engines as Record<string, unknown>)['node'] : undefined;
      if (typeof stated !== 'string') {
        disagreed.push(`${one.name} ships engines.node ${String(stated)}, where ${ROOT_MANIFEST} declares "${wanted}"`);
        continue;
      }
      // Compared as a range and not as text, because a range is the promise the field makes. A packed
      // manifest written `>= 26.13.0 <27` states this one promise; one written `>=26.0.0` does not, and a
      // text match reads the first as a defect and the second as clean.
      if (!rangesAgree(parseRange(stated, `${one.name} engines.node`), declared)) {
        disagreed.push(`${one.name} ships engines.node "${stated}", which is not the promise ${ROOT_MANIFEST} declares as "${wanted}"`);
      }
    }
    expect(disagreed, disagreed.join('\n')).toEqual([]);
  });
});

describe('the installed tree a consumer ends up with', () => {
  it('installs the six as one copy of each, resolved inside the prefix and nowhere else', () => {
    const answer = consumerAnswer();
    const outside: string[] = [];
    for (const [name, resolved] of Object.entries(answer.resolved)) {
      const normal = asUrlPath(resolved);
      if (!normal.includes('/node_modules/@ashaveri/')) outside.push(`${name} resolved to ${resolved}`);
      if (normal.startsWith(asUrlPath(PACKAGE_PARENT))) outside.push(`${name} resolved back into the workspace at ${resolved}`);
    }
    expect(outside, `an installed module was read from outside the prefix:\n${outside.join('\n')}`).toEqual([]);
    const duplicated: string[] = [];
    for (const one of packed) {
      const installed = path.join(prefix, 'node_modules', ...one.name.split('/'));
      expect(existsSync(installed), `${one.name} is not installed at the prefix root`).toBe(true);
      // A second copy of a published package can sit under its own directory or under a sibling's, and the
      // two are one fault: the deeper copy is the one a resolver reaches first for the package holding it, so
      // the host imports a reader that the prefix root, and every check weighing it, never read. Listing the
      // scoped directory each installed package holds weighs both shapes, because neither one depends on the
      // nested name matching the name of the directory holding it.
      const scoped = path.join(installed, 'node_modules', SCOPE);
      if (existsSync(scoped)) {
        for (const entry of readdirSync(scoped, { withFileTypes: true })) {
          if (!entry.isDirectory()) continue;
          const nested = `${SCOPE}${entry.name}`;
          if (!packed.some((copy) => copy.name === nested)) continue;
          duplicated.push(
            `${nested} sits inside ${one.name} at ${asUrlPath(path.relative(prefix, path.join(scoped, entry.name)))}`,
          );
        }
      }
      expect(String(installedManifest(one.name)['version']), `${one.name} installed a different version than it packed`).toBe(
        String(packedOf(one.name).manifest['version']),
      );
    }
    expect(duplicated, `a sibling installed twice, which is two readers of one format:\n${duplicated.join('\n')}`).toEqual([]);
  });

  it('answers every import of the published surface with real exports', () => {
    const answer = consumerAnswer();
    for (const [name, count] of Object.entries(answer.exportCount)) {
      expect(count, `${name} imported and exported nothing`).toBeGreaterThan(0);
    }
    expect(answer.sdkSurface).toEqual({ client: 'function', wrap: 'function' });
    expect(answer.rows, 'the installed fixtures read no rows').toBeGreaterThan(0);
  });

  it('verifies a published receipt at each payload version through the installed library', () => {
    const answer = consumerAnswer();
    expect(Object.keys(answer.verified).sort()).toEqual(['v1', 'v2']);
    expect(answer.verified['v1']?.payloadVersion).toBe(1);
    expect(answer.verified['v2']?.payloadVersion).toBe(2);
    expect(answer.verified['v1']?.model).toBe(answer.verified['v2']?.model);
  });

  it('refuses the tampered published receipt through the installed library', () => {
    const answer = consumerAnswer();
    expect(
      answer.tampered,
      `the installed library answered ${answer.tamperedRow} with ${answer.tampered}, where the published row states ${answer.tamperedStated}`,
    ).toBe(answer.tamperedStated);
  });

  it('ships the normative CDDL and JSON twins beside the installed reader', () => {
    const receiptDir = path.join(prefix, 'node_modules', '@ashaveri', 'receipt');
    const shipped = readdirSync(receiptDir);
    for (const cddl of ['receipt.cddl', 'pack.cddl', 'export.cddl', 'redaction.cddl', 'destruction-receipt.cddl', 'manifest.cddl', 'epoch-inventory.cddl', 'anchor-provenance.cddl']) {
      expect(shipped.includes(cddl), `${cddl} is in the manifest's files list and not in the installed package`).toBe(true);
    }
    const schemas = readdirSync(path.join(receiptDir, 'schemas'));
    expect(schemas.length, 'the installed receipt package holds no JSON twins to read').toBeGreaterThan(0);
    expect(schemas).toContain('receipt-v1.schema.json');
    expect(schemas).toContain('receipt-v2.schema.json');
  });
});

/**
 * The command the installed manifest says it ships. A consumer reaches the binary through the `bin` field the
 * installer read, so this resolves what that field names rather than the file this file happens to expect.
 */
function installedCommand(): string {
  const bin = installedManifest('@ashaveri/cli')['bin'];
  const target = typeof bin === 'object' && bin !== null ? Object.values(bin as Record<string, unknown>)[0] : bin;
  if (typeof target !== 'string') throw new Error(`the installed cli manifest names no bin target: ${JSON.stringify(bin)}`);
  return path.join(prefix, 'node_modules', '@ashaveri', 'cli', target.replace(/^\.\//u, ''));
}

describe('the installed command on the same bytes', () => {
  it('accepts the published receipt and names its content type', () => {
    const cli = installedCommand();
    expect(existsSync(cli), `the installed cli manifest names ${cli}, which the install did not write`).toBe(true);
    const accepted = runNode(cli, ['verify-handover', 'installed-accepted.cbor', '--key', consumerAnswer().keyBase64Url, '--json'], prefix);
    expect(accepted.status, `the installed command refused an accepted receipt: ${accepted.stderr.slice(0, 400)}`).toBe(0);
    const verdict = JSON.parse(accepted.stdout) as { ok?: boolean; contentType?: string };
    expect(verdict.ok).toBe(true);
    expect(verdict.contentType).toBe('ashaveri/receipt');
  });

  it('refuses the tampered receipt with the code the fixtures state beside it', () => {
    const answer = consumerAnswer();
    const refused = runNode(installedCommand(), ['verify-handover', 'installed-tampered.cbor', '--key', answer.keyBase64Url, '--json'], prefix);
    expect(refused.status, 'the installed command exited zero on bytes the published row refuses').not.toBe(0);
    const verdict = JSON.parse(refused.stdout) as { ok?: boolean; code?: string };
    expect(verdict.ok).toBe(false);
    expect(
      verdict.code,
      `the installed command answered ${answer.tamperedRow} with ${String(verdict.code)}, where the published row states ${answer.tamperedStated}`,
    ).toBe(answer.tamperedStated);
  });

  it('leaves no trace of the checkout it was installed from in the installed manifest', () => {
    for (const one of packed) {
      const serialized = JSON.stringify(installedManifest(one.name));
      expect(serialized.includes('workspace:'), `${one.name} installed a manifest still naming the workspace protocol`).toBe(false);
      // Both directories, because a local pack can name either: npm records no `_resolved` entry for a
      // tarball install, so the scratch directory the tarball was packed into travels into an installed
      // manifest as readily as the checkout it was packed from. Each is read in both spellings a manifest
      // can hold a directory in, the forward slashes a URL or a hand-written field carries and the native
      // separators `JSON.stringify` doubles, which is the spelling this machine's own paths arrive in and
      // the one a comparison that only takes separators out reads as some other directory entirely.
      for (const [label, leaked] of [
        ['the checkout it was packed from', REPO_ROOT],
        ['the directory it was packed into', scratch],
      ] as const) {
        expect(
          carriesPath(serialized, leaked),
          `${one.name} installed a manifest carrying a path to ${label}: ${asUrlPath(leaked)}`,
        ).toBe(false);
      }
    }
  });

  it('catches a leaked directory in the spelling its own separators are escaped in', () => {
    // The plantings this check was written against could only ever carry one of the two spellings, because
    // a scratch path on a POSIX runner holds no separator that JSON escapes. So the doubled spelling is
    // shown here from text rather than from a filesystem: the claim the check above makes is that a leak is
    // caught whichever way its separators are written, and a runner that cannot write them the other way is
    // no evidence that it would have noticed.
    const forward = asUrlPath(REPO_ROOT);
    const native = forward.split('/').join('\\');
    expect(
      carriesPath(JSON.stringify({ _resolved: native }), REPO_ROOT),
      `a manifest holding the separators-escaped ${native} went uncaught`,
    ).toBe(true);
    expect(
      carriesPath(JSON.stringify({ _resolved: forward }), REPO_ROOT),
      `a manifest holding the forward-spelled ${forward} went uncaught`,
    ).toBe(true);
    expect(
      carriesPath(JSON.stringify({ _resolved: '/nowhere/this/run/created' }), REPO_ROOT),
      'the comparison flags a directory it was never handed',
    ).toBe(false);
  });
});

/** The consumer's answer, or the reason the run has none yet. */
function consumerAnswer(): ConsumerReport {
  if (consumer === null) throw new Error('the pack, install and consumer run never produced an answer');
  return consumer;
}
