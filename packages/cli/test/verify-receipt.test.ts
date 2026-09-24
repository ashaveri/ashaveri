import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  decodeSealedDeploymentManifest,
  generateSigningKey,
  sealDeploymentManifest,
  toHex,
  type SigningKey,
} from '@ashaveri/receipt';

/**
 * `ashaveri verify-receipt`, driven by the published receipt vectors.
 *
 * The receipt bytes come from `packages/fixtures/data` and the verdicts asserted against them are the
 * ones that directory's own manifest states, so this suite is not free to redefine what a fixture
 * means. The policy and the deployment manifest are written per run rather than committed: they are
 * the caller's side of the transaction, and the same key and issuer appear in both because a real
 * deployment's do.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));
const SPEC = fileURLToPath(new URL('../../../docs/receipt-spec.md', import.meta.url));

/** A published receipt's JSON twin: the payload as the fixtures spell it, which is hex throughout. */
interface ReceiptJson {
  protectedHeader: { alg: string; kid: string; typ: string };
  payload: {
    v: number;
    iss: string;
    ins: string;
    iat: number;
    nce: string;
    req: string;
    res: string;
    mdl: string;
    wts: string;
    meas: { tee: string; m: string };
    att: { d: string; ts: number; url: string };
    epk: number;
    tok: { p: number; c: number };
    mk?: { sch: string; d: string };
  };
}

function receiptJson(name: string): ReceiptJson {
  return JSON.parse(readFileSync(`${DATA}receipts/${name}.json`, 'utf8')) as ReceiptJson;
}

/** The receipt signing key the fixtures are issued under, as `keys/receipt-key-v1.json` publishes it. */
const KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as {
  kid: string;
  publicKey: string;
};
const KID = KEY.kid;
const PUBLIC_KEY = Buffer.from(KEY.publicKey, 'hex').toString('base64url');

/** The deployment the fixture receipts are issued by, read out of one of them. */
const VALID = receiptJson('receipt-valid-v1');
const SOFTWARE = receiptJson('receipt-software-v1');
const MARKED = receiptJson('receipt-marked-v2');
const ISSUER = VALID.payload.iss;
const INSTANCE = VALID.payload.ins;
const NONCE = VALID.payload.nce;
const REQUEST_DIGEST = VALID.payload.req;
const RESPONSE_DIGEST = VALID.payload.res;
/** The instant `iat` names, so the policy's windows close around the receipt rather than on today. */
const NOW = new Date(VALID.payload.iat * 1000).toISOString();

/** A measurement of the right width for each environment kind, which is what a policy pin has to be. */
const WRONG_SOFTWARE = '0'.repeat(64);

/** A second key's public half, for a manifest that declares a rotation this receipt did not use. */
const OTHER_KEY = Buffer.alloc(32, 7).toString('base64url');

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-verify-receipt-'));

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(args: string[], input?: Uint8Array): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    input: input === undefined ? undefined : Buffer.from(input),
    encoding: 'utf8',
    timeout: 10_000,
    killSignal: 'SIGKILL',
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** One file per call, under a directory that disappears with the run. */
let writtenCount = 0;
function written(name: string, data: string | Buffer): string {
  const path = join(tempDir, `${writtenCount++}-${name}`);
  writeFileSync(path, data);
  return path;
}

function receiptPath(name: string): string {
  return `${DATA}receipts/${name}.cbor`;
}

/** A deployment manifest in the shape the SDK parses, as the caller would hand one over. */
function manifestDocument(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    iss: ISSUER,
    ins: INSTANCE,
    epk: VALID.payload.epk,
    keys: [{ kid: KID, alg: 'Ed25519', publicKey: PUBLIC_KEY }],
    models: [{ id: VALID.payload.mdl, wts: VALID.payload.wts }],
    meas: { tee: VALID.payload.meas.tee, m: VALID.payload.meas.m },
    ...overrides,
  });
}

/** A policy document pinning all four families, which is what a customer of a deployment writes. */
function policyDocument(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    issuers: [ISSUER],
    instances: [INSTANCE],
    keys: { [KID]: PUBLIC_KEY },
    measurements: { [VALID.payload.meas.tee]: [VALID.payload.meas.m], [SOFTWARE.payload.meas.tee]: [SOFTWARE.payload.meas.m] },
    maxReceiptAgeSeconds: 300,
    maxEvidenceAgeSeconds: 900,
    ...overrides,
  });
}

function policyFile(overrides: Record<string, unknown> = {}): string {
  return written('policy.json', policyDocument(overrides));
}

function manifestFile(overrides: Record<string, unknown> = {}): string {
  return written('manifest.json', manifestDocument(overrides));
}

/**
 * The key a sealed copy of this deployment's document is sealed under, and a second key that seals
 * nothing here. Built once because every case below has to name the same public half on the command
 * line as the file does in its header.
 */
const SEALING_KEY = generateSigningKey();
const SEALING_KID = toHex(SEALING_KEY.kid);
const STRANGER_KEY = generateSigningKey();
const STRANGER_KID = toHex(STRANGER_KEY.kid);

/** The designation string `--manifest-key` takes for a key: its public half, canonical base64url. */
function designationOf(key: SigningKey): string {
  return Buffer.from(key.publicKey).toString('base64url');
}

const DESIGNATED_SEALING_KEY = designationOf(SEALING_KEY);
const DESIGNATED_STRANGER_KEY = designationOf(STRANGER_KEY);

/** A manifest file in the shape a deployment that was handed a signing identity serves it. */
function sealedManifestFile(text: string, key: SigningKey): string {
  return written('manifest.cbor', Buffer.from(sealDeploymentManifest(new TextEncoder().encode(text), key)));
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * A spelling of a canonical key that decodes to its bytes without being what any encoder writes.
 *
 * The last character of a 43-character encoding carries two bits an encoder never sets, so the other
 * three alphabet positions in its group of four decode to the same 32 bytes. That is the case the
 * policy file's `base64Url32` refuses, and this flag has to refuse it the same way or copying a key
 * between the two channels gives two answers.
 */
function nonCanonicalSpelling(value: string): string {
  const last = BASE64URL_ALPHABET.indexOf(value.charAt(value.length - 1));
  const neighbour = last % 4 === 3 ? last - 1 : last + 1;
  return `${value.slice(0, -1)}${BASE64URL_ALPHABET[neighbour]}`;
}

/**
 * A sealed manifest whose document was replaced, in place, by one exactly as long.
 *
 * The payload travels as a byte string, so a same-length swap leaves an envelope that still decodes
 * and leaves the signature as the only thing that can notice the bytes are not the ones that were
 * signed. That is the state of a manifest that moved after a deployment sealed it.
 */
function sealedAroundSwappedDocument(signed: string, swapped: string, key: SigningKey): Buffer {
  const original = new TextEncoder().encode(signed);
  const replacement = Buffer.from(swapped, 'utf8');
  if (original.length !== replacement.length) {
    throw new Error('a swapped payload has to be exactly as long, or the envelope would not decode');
  }
  // The document goes in as a plain `Uint8Array` rather than the `Buffer` the search below needs: the
  // canonical CBOR writer in the format package takes a `Buffer` apart as the object it is instead of
  // encoding its bytes, and the envelope that comes out is nothing a reader calls a sealed manifest.
  const sealed = Buffer.from(sealDeploymentManifest(original, key));
  const at = sealed.indexOf(Buffer.from(original));
  if (at < 0) {
    throw new Error('the sealed envelope carries no copy of the document it was built from');
  }
  replacement.copy(sealed, at);
  return sealed;
}

interface RunOptions {
  readonly receipt?: string;
  readonly policy?: string;
  readonly manifest?: string;
  readonly manifestKeys?: readonly string[];
  readonly nonce?: string;
  readonly requestBody?: string;
  readonly requestDigest?: string;
  readonly responseBody?: string;
  readonly responseDigest?: string;
  readonly now?: string;
  readonly json?: boolean;
}

/**
 * A full, honest run: every input the verdict is reached from.
 *
 * Each piece is replaceable on its own because every refusal this command owes is a refusal of one
 * input, and a test that rebuilt the whole command line per case could not show which one moved. A
 * digest is left out only when the bytes it stands for are given, which is why the two share a slot.
 */
function argsFor(options: RunOptions): string[] {
  const args = ['verify-receipt', options.receipt ?? receiptPath('receipt-valid-v1')];
  const requestDigest = options.requestBody === undefined ? (options.requestDigest ?? REQUEST_DIGEST) : undefined;
  const flags: [string, string | readonly string[] | undefined][] = [
    ['--policy', options.policy ?? policyFile()],
    ['--manifest', options.manifest ?? manifestFile()],
    ['--manifest-key', options.manifestKeys],
    ['--nonce', options.nonce ?? NONCE],
    ['--request-body', options.requestBody],
    ['--request-hash', requestDigest],
    ['--response-body', options.responseBody],
    ['--response-hash', options.responseBody === undefined ? (options.responseDigest ?? RESPONSE_DIGEST) : undefined],
    ['--now', options.now ?? NOW],
  ];
  for (const [flag, value] of flags) {
    if (value === undefined) continue;
    for (const one of typeof value === 'string' ? [value] : value) {
      // Spelled as one token because a base64url value may begin with a dash, and a bare dash begins
      // an option to `parseArgs`, not the value of the one before it.
      args.push(`${flag}=${one}`);
    }
  }
  if (options.json ?? true) {
    args.push('--json');
  }
  return args;
}

function verdictOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/**
 * The body of one heading in a markdown document, up to the next heading of its own level or a
 * shallower one. Bounding the read is the point: a claim pinned to a section must not be satisfiable
 * by the same words standing somewhere else in the file.
 */
function sectionBody(markdown: string, heading: string): string {
  const lines = markdown.split('\n');
  const start = lines.indexOf(heading);
  if (start < 0) {
    throw new Error(`${heading} is not a heading in the specification`);
  }
  const depth = heading.search(/[^#]/u);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => /^#{1,6} /u.test(line) && line.search(/[^#]/u) <= depth);
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

/** The response bytes a published marking vector publishes, as the file the caller would keep. */
function markingBody(vector: string): string {
  const suite = JSON.parse(readFileSync(`${DATA}marking-v1.json`, 'utf8')) as {
    vectors: { name: string; responseBase64Url: string; dHex: string }[];
  };
  const found = suite.vectors.find((each) => each.name === vector);
  if (found === undefined) {
    throw new Error(`the marking suite publishes no vector named '${vector}'`);
  }
  return written(`${vector}.response`, Buffer.from(found.responseBase64Url, 'base64url'));
}

describe('ashaveri verify-receipt', () => {
  it('verifies a published receipt from files alone and prints every pin it matched', () => {
    const human = runCli(argsFor({ json: false }));
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain('receipt verified (COSE_Sign1, payload v1, EdDSA over the signed bytes)');
    expect(human.stdout).toContain(`  kid:              ${KID}`);
    expect(human.stdout).toContain(`  issuer:           ${ISSUER}`);
    expect(human.stdout).toContain(`  nonce:            ${NONCE} (the value this run was told to expect)`);
    expect(human.stdout).toContain(
      `  key epoch:        ${VALID.payload.epk}, adjudicated against the manifest's declaration (current-epoch): epoch ${VALID.payload.epk} is the only epoch this manifest declares, and the key is one of the keys it lists`,
    );
    expect(human.stdout).toContain('  manifest seal:    the deployment manifest is unsigned');
    expect(human.stdout).toContain(`  pinned:           issuer: the policy's 'issuers' pin matched`);
    expect(human.stdout).toContain('  pinned:           receipt key:');
    expect(human.stdout).toContain('  pinned:           measurement:');
    expect(human.stdout).toContain('  not checked:      the evidence document behind att.d');
  });

  it('reads the receipt from stdin when the argument is -', () => {
    const bytes = readFileSync(receiptPath('receipt-valid-v1'));
    expect(runCli(argsFor({ receipt: '-' }), bytes).status).toBe(0);
  });

  it('reports a machine-readable verdict naming the pins, the files and the windows', () => {
    const policy = policyFile();
    const manifest = manifestFile();
    const result = runCli(argsFor({ policy, manifest }));
    expect(result.status).toBe(0);
    const out = verdictOf(result);
    expect(out.ok).toBe(true);
    expect(out.format).toBe('COSE_Sign1');
    expect(out.payloadVersion).toBe(1);
    expect(out.kid).toBe(KID);
    expect(out.issuer).toBe(ISSUER);
    expect(out.instance).toBe(INSTANCE);
    expect(out.nonce).toBe(NONCE);
    expect(out.keyEpoch).toEqual({
      receipt: VALID.payload.epk,
      manifest: VALID.payload.epk,
      accepted: true,
      basis: 'current-epoch',
      validFrom: null,
      validTo: null,
      superseded: false,
      reason: expect.stringContaining('the only epoch this manifest declares'),
    });
    expect(out.manifestSeal).toEqual({
      sealed: false,
      authenticated: false,
      kid: null,
      policyDesignatesManifestKey: false,
      advisory: expect.stringContaining('no manifest signing key is pinned'),
    });
    expect(out.measurement).toEqual({ tee: VALID.payload.meas.tee, m: VALID.payload.meas.m });
    expect(out.requestDigest).toEqual({ sha256: REQUEST_DIGEST, takenFrom: 'the --request-hash value as written' });
    expect(out.markedRegion).toBeNull();
    expect(out.evidence).toEqual({ digest: VALID.payload.att.d, timestamp: VALID.payload.att.ts, documentChecked: false });
    expect(out.policy).toEqual({ digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u), file: policy });
    expect(out.manifest).toEqual({ file: manifest, issuer: ISSUER, instance: INSTANCE, declaredKeys: [KID] });
    expect(out.windows).toEqual({ receiptSeconds: 300, evidenceSeconds: 900 });
    expect(out.pinned).toHaveLength(4);
    // A policy file format carries no field for manifest signing keys and this run named none on the
    // command line, so this family is the one question neither channel asked.
    expect(out.notPinned).toEqual([
      "manifest key: the policy file names no 'manifestKeys' pin and no --manifest-key was given, so no seal was checked",
    ]);
    expect(out.manifestKeyDesignation).toEqual([]);
    expect(out.manifestKeyDesignationOutsidePolicyDigest).toBe(false);
    expect(out.notChecked).toEqual(['the evidence document behind att.d, which this command does not fetch']);
  });

  it('reports the seal a sealed manifest file carries and says what it proves', () => {
    // The wrapper is read from the first byte of the file rather than from its name, and nothing in a
    // policy file can designate a manifest signer, so the honest answer is that the bytes are whole and
    // their author is unknown to this run.
    const key = generateSigningKey();
    const sealed = sealDeploymentManifest(new TextEncoder().encode(manifestDocument()), key);
    const manifest = written('manifest.cbor', Buffer.from(sealed));
    const result = runCli(argsFor({ manifest }));
    expect(result.status).toBe(0);
    const out = verdictOf(result);
    expect(out.manifestSeal).toEqual({
      sealed: true,
      authenticated: false,
      kid: toHex(key.kid),
      policyDesignatesManifestKey: false,
      advisory: expect.stringContaining('names no manifest signing key'),
    });
    expect(out.keyEpoch).toMatchObject({ accepted: true, basis: 'current-epoch' });
    const human = runCli(argsFor({ manifest, json: false }));
    expect(human.stdout).toContain(`  manifest seal:    the deployment manifest arrived sealed under key ${toHex(key.kid)}`);
  });

  /**
   * The rows of the manifest-authentication table that only a designated key can reach, in both
   * directions. The two advisory rows are the cases above, which a designation leaves exactly as they
   * were; the four refusals below are what naming a signer costs, and the pass among them is what the
   * flag exists to make possible.
   */
  describe('--manifest-key', () => {
    it('authenticates a sealed manifest under a designated key and names where that key came from', () => {
      const policy = policyFile();
      const manifest = sealedManifestFile(manifestDocument(), SEALING_KEY);
      const result = runCli(argsFor({ policy, manifest, manifestKeys: [DESIGNATED_SEALING_KEY] }));
      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
      const out = verdictOf(result);
      expect(out.manifestSeal).toEqual({
        sealed: true,
        authenticated: true,
        kid: SEALING_KID,
        policyDesignatesManifestKey: true,
        advisory: null,
      });
      expect(out.manifestKeyDesignation).toEqual([
        { kid: SEALING_KID, publicKey: DESIGNATED_SEALING_KEY, source: '--manifest-key' },
      ]);
      expect(out.manifestKeyDesignationOutsidePolicyDigest).toBe(true);
      expect(out.pinned).toContain(
        'manifest key: the manifest seal verified under a key designated by --manifest-key on this command line, which no part of the cited policy digest covers',
      );
      expect(out.notPinned).toEqual([]);

      // The designation joins the policy the session enforces and not the document whose digest the run
      // cites: the same file hashes the same whether or not a key was typed beside it, which is the
      // asymmetry every line above is there to make visible.
      const unDesignated = runCli(argsFor({ policy, manifest: manifestFile() }));
      expect(unDesignated.status).toBe(0);
      expect(verdictOf(unDesignated).policy).toEqual(out.policy);

      const human = runCli(argsFor({ policy, manifest, manifestKeys: [DESIGNATED_SEALING_KEY], json: false }));
      expect(human.stderr).toBe('');
      expect(human.status).toBe(0);
      expect(human.stdout).toContain(
        `  designated key:   ${SEALING_KID} = ${DESIGNATED_SEALING_KEY} (designated by --manifest-key on this command line)`,
      );
      expect(human.stdout).toContain(
        '  key source:       the policy digest above designates no manifest signing key, so the seal below was checked against what this command line handed over',
      );
      expect(human.stdout).toContain(
        `  manifest seal:    sealed, and verified under the manifest key for ${SEALING_KID}, designated by --manifest-key on this command line`,
      );
      expect(human.stdout).toContain('  pinned:           manifest key:');
    });

    it('refuses a sealed manifest whose seal was made by a key nobody designated', () => {
      const manifest = sealedManifestFile(manifestDocument(), SEALING_KEY);
      const result = runCli(argsFor({ manifest, manifestKeys: [DESIGNATED_STRANGER_KEY] }));
      expect(result.status).toBe(1);
      const out = verdictOf(result);
      expect(out.code).toBe('MANIFEST_NOT_AUTHENTICATED');
      expect(out.message).toContain(`sealed under key ${SEALING_KID}, which this policy does not designate`);
    });

    it('refuses a sealed manifest whose bytes moved after it was signed, and only after a key made the check possible', () => {
      // The swapped document differs from the sealed one in one weights digest, which decides nothing on
      // this path: the seal is verified before the document is parsed, so the refusal can only be about
      // the bytes having moved. Sealing the same swapped document under the same key is the control that
      // says so, and it passes.
      const moved = manifestDocument({
        models: [{ id: VALID.payload.mdl, wts: 'f'.repeat(64) }],
      });
      expect(moved.length).toBe(manifestDocument().length);
      const swapped = sealedAroundSwappedDocument(manifestDocument(), moved, SEALING_KEY);
      const seal = decodeSealedDeploymentManifest(swapped);
      expect(toHex(seal.header.kid)).toBe(SEALING_KID);
      expect(new TextDecoder().decode(seal.payloadBytes)).toBe(moved);

      const result = runCli(argsFor({ manifest: written('swapped.cbor', swapped), manifestKeys: [DESIGNATED_SEALING_KEY] }));
      expect(result.status).toBe(1);
      const out = verdictOf(result);
      expect(out.code).toBe('MANIFEST_SIGNATURE_INVALID');
      expect(out.message).toContain('does not verify under the key pinned for it');

      const sealedMoved = sealedManifestFile(moved, SEALING_KEY);
      const control = runCli(argsFor({ manifest: sealedMoved, manifestKeys: [DESIGNATED_SEALING_KEY] }));
      expect(control.status).toBe(0);
      expect(verdictOf(control).manifestSeal).toMatchObject({ authenticated: true, kid: SEALING_KID });
    });

    it('refuses an unsigned manifest once a key has been designated, which is the verdict the flag changes', () => {
      const manifest = manifestFile();
      const result = runCli(argsFor({ manifest, manifestKeys: [DESIGNATED_SEALING_KEY] }));
      expect(result.status).toBe(1);
      const out = verdictOf(result);
      expect(out.code).toBe('MANIFEST_NOT_AUTHENTICATED');
      expect(out.message).toContain('served an unsigned manifest while this policy designates 1 key');
    });

    it('leaves an unsigned manifest an advisory when no key was designated, which is the default the flag does not touch', () => {
      const manifest = manifestFile();
      const result = runCli(argsFor({ manifest }));
      expect(result.status).toBe(0);
      const out = verdictOf(result);
      expect(out.manifestSeal).toMatchObject({
        sealed: false,
        authenticated: false,
        kid: null,
        policyDesignatesManifestKey: false,
        advisory: expect.stringContaining('the deployment manifest is unsigned'),
      });
      expect(out.manifestKeyDesignation).toEqual([]);
      expect(out.manifestKeyDesignationOutsidePolicyDigest).toBe(false);
      expect(out.notPinned).toEqual([
        "manifest key: the policy file names no 'manifestKeys' pin and no --manifest-key was given, so no seal was checked",
      ]);
      const human = runCli(argsFor({ manifest, json: false }));
      expect(human.status).toBe(0);
      expect(human.stdout).toContain('  manifest seal:    the deployment manifest is unsigned');
      expect(human.stdout).not.toContain('  designated key:');
      expect(human.stdout).not.toContain('  key source:');
    });

    it('refuses a key that is not the canonical base64url spelling of its own bytes, and names the one that is', () => {
      const spelled = nonCanonicalSpelling(DESIGNATED_SEALING_KEY);
      expect(spelled).not.toBe(DESIGNATED_SEALING_KEY);
      const result = runCli(argsFor({ manifestKeys: [spelled], json: false }));
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        `--manifest-key is not the canonical base64url spelling of its own bytes, which are ${DESIGNATED_SEALING_KEY}`,
      );
    });

    it('refuses an argument that is not a manifest signing key by the flag that carried it', () => {
      const short = runCli(argsFor({ manifestKeys: [DESIGNATED_SEALING_KEY.slice(0, 42)], json: false }));
      expect(short.status).toBe(2);
      expect(short.stderr).toContain(
        '--manifest-key must be the base64url of 32 bytes, which is 43 characters and no padding',
      );

      const notAKey = runCli(argsFor({ manifestKeys: ['not-a-key'], json: false }));
      expect(notAKey.status).toBe(2);
      expect(notAKey.stderr).toContain('--manifest-key must be the base64url of 32 bytes');
      expect(notAKey.stderr).toContain("Try 'ashaveri --help'");
    });

    it('checks every designated key, whichever place in the list the matching one sits', () => {
      const manifest = sealedManifestFile(manifestDocument(), SEALING_KEY);
      for (const keys of [[DESIGNATED_STRANGER_KEY, DESIGNATED_SEALING_KEY], [DESIGNATED_SEALING_KEY, DESIGNATED_STRANGER_KEY]]) {
        const result = runCli(argsFor({ manifest, manifestKeys: keys }));
        expect(result.status).toBe(0);
        const out = verdictOf(result);
        expect(out.manifestSeal).toMatchObject({ authenticated: true, kid: SEALING_KID });
        expect(out.manifestKeyDesignation).toEqual(
          keys.map((one) => ({
            kid: one === DESIGNATED_SEALING_KEY ? SEALING_KID : STRANGER_KID,
            publicKey: one,
            source: '--manifest-key',
          })),
        );
      }
    });

    it('counts one designated key once, however many times it was typed', () => {
      const manifest = sealedManifestFile(manifestDocument(), SEALING_KEY);
      const result = runCli(argsFor({ manifest, manifestKeys: [DESIGNATED_SEALING_KEY, DESIGNATED_SEALING_KEY] }));
      expect(result.status).toBe(0);
      expect(verdictOf(result).manifestKeyDesignation).toEqual([
        { kid: SEALING_KID, publicKey: DESIGNATED_SEALING_KEY, source: '--manifest-key' },
      ]);
    });

    it('names the flag in the help text and in its own line of the usage', () => {
      const help = runCli(['--help']);
      expect(help.stdout).toContain('[--manifest-key <b64url>]...');
      expect(help.stdout).toContain('--manifest-key <b64url>');
      expect(help.stdout).toContain('MANIFEST_NOT_AUTHENTICATED');
    });

    it('states the designation channel once in the specification, spelling the flag as this command does', () => {
      // The specification is where a reader learns that a manifest signing key has to arrive from
      // somewhere the deployment does not control, and this command is where one arrives. Two voices
      // for one rule is how a document starts disagreeing with itself, so the channel is named in one
      // place, under the section that decides what a policy file cannot carry, and the flag it names is
      // the flag this program parses.
      const spec = readFileSync(SPEC, 'utf8');
      const mentions = spec.split('--manifest-key').length - 1;
      expect(mentions).toBe(1);
      const section = sectionBody(spec, '### 5.1 Verification modes');
      expect(section).toContain('ashaveri verify-receipt --manifest-key <base64url>');
      expect(section).toContain('repeatable');
      expect(section).toContain('the digest covers none of them');
      expect(section).toContain('the policy file format carries no such field');
      const help = runCli(['--help']);
      expect(help.stdout).toContain('--manifest-key');
      expect(help.stdout).toContain('Repeatable, one key per flag');
    });
  });

  it('refuses a signed receipt handed to it as a manifest', () => {
    // Both documents are `COSE_Sign1`, both verify under a key a reader trusted, and only the protected
    // content type says which claim is being read, so the confusion is a refusal rather than a verdict.
    const result = runCli(argsFor({ manifest: receiptPath('receipt-valid-v1') }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('BAD_PROTECTED_HEADER');
  });

  it('adjudicates the epoch against a declared window and reports the retention', () => {
    const keys = [
      { kid: KID, alg: 'Ed25519', publicKey: PUBLIC_KEY, epk: VALID.payload.epk, validFrom: VALID.payload.iat - 1000 },
      { kid: 'e'.repeat(64), alg: 'Ed25519', publicKey: OTHER_KEY, epk: 4, validFrom: VALID.payload.iat + 1000 },
    ];
    const result = runCli(argsFor({ manifest: manifestFile({ epk: 4, keys }) }));
    expect(result.status).toBe(0);
    expect(verdictOf(result).keyEpoch).toEqual({
      receipt: VALID.payload.epk,
      manifest: 4,
      accepted: true,
      basis: 'windows',
      validFrom: VALID.payload.iat - 1000,
      validTo: VALID.payload.iat + 1000,
      superseded: true,
      reason: expect.stringContaining('was superseded by 4 and the deployment still retains its key'),
    });
    const human = runCli(argsFor({ manifest: manifestFile({ epk: 4, keys }), json: false }));
    expect(human.stdout).toContain(
      `  key epoch:        ${VALID.payload.epk}, adjudicated against the manifest's declaration (windows, window ${VALID.payload.iat - 1000} to ${String(VALID.payload.iat + 1000)})`,
    );
  });

  it('refuses a receipt whose epoch the manifest never declared', () => {
    const keys = [{ kid: KID, alg: 'Ed25519', publicKey: PUBLIC_KEY, epk: 9, validFrom: 1 }];
    const result = runCli(argsFor({ manifest: manifestFile({ epk: 9, keys }) }));
    expect(result.status).toBe(1);
    const out = verdictOf(result);
    expect(out.code).toBe('MANIFEST_EPOCH_UNDECLARED');
    expect(out.message).toContain(`epoch ${VALID.payload.epk} is declared by no entry of this manifest`);
  });

  it('refuses a receipt stamped outside the window its epoch was given', () => {
    const keys = [
      { kid: KID, alg: 'Ed25519', publicKey: PUBLIC_KEY, epk: VALID.payload.epk, validFrom: VALID.payload.iat + 1 },
    ];
    const result = runCli(argsFor({ manifest: manifestFile({ keys }) }));
    expect(result.status).toBe(1);
    const out = verdictOf(result);
    expect(out.code).toBe('MANIFEST_EPOCH_DISAGREES');
    expect(out.message).toContain('outside the epoch');
  });

  it('names which pins a thin policy left unchecked instead of counting them as passes', () => {
    const thin = written('thin-policy.json', JSON.stringify({ v: 1, keys: { [KID]: PUBLIC_KEY } }));
    const result = runCli(argsFor({ policy: thin }));
    expect(result.status).toBe(0);
    const out = verdictOf(result);
    expect(out.pinned).toEqual(["receipt key: the policy's 'keys' pin matched"]);
    expect(out.notPinned).toEqual([
      "issuer: the policy names no 'issuers' pin, so nothing was compared",
      "instance: the policy names no 'instances' pin, so nothing was compared",
      "manifest key: the policy file names no 'manifestKeys' pin and no --manifest-key was given, so no seal was checked",
      "measurement: the policy names no 'measurements' pin, so nothing was compared",
    ]);
  });

  it('checks a marked receipt against the response bytes and reports the region it read', () => {
    const body = markingBody('buffered-member');
    const result = runCli(argsFor({ receipt: receiptPath('receipt-marked-v2'), responseBody: body, json: false }));
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`  response digest:  ${MARKED.payload.res}, sha256 of the bytes in ${body}`);
    expect(result.stdout).toContain(`  marked region:    ${MARKED.payload.mk?.d} (provenance-v1)`);
    const json = runCli(argsFor({ receipt: receiptPath('receipt-marked-v2'), responseBody: body }));
    expect(verdictOf(json).markedRegion).toEqual({ scheme: 'provenance-v1', sha256: MARKED.payload.mk?.d });
  });

  it('refuses to check a marked receipt on a hand-written response digest', () => {
    const result = runCli(argsFor({ receipt: receiptPath('receipt-marked-v2'), json: false }));
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('this is a v2 receipt');
    expect(result.stderr).toContain('--response-body is required and --response-hash cannot carry that check');
  });

  it('refuses a marked receipt whose response bytes no longer carry the attested region', () => {
    const body = markingBody('region-stripped');
    const result = runCli(argsFor({ receipt: receiptPath('receipt-marked-v2'), responseBody: body }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('RESPONSE_HASH_MISMATCH');
  });

  it('drives every published vector to the verdict the fixtures manifest states', () => {
    const published = JSON.parse(readFileSync(`${DATA}manifest.json`, 'utf8')) as {
      fixtures: { name: string; path: string; expected: string }[];
    };
    const stated = new Map(published.fixtures.map((each) => [each.name, each]));
    expect(stated.size).toBeGreaterThan(4);
    // The marked vector is covered by its own three cases above, because its check is carried by the
    // response bytes rather than by a digest; the rest run here on the digests their JSON twins state.
    const drivenApart = ['receipt-marked-v2'];
    for (const [name, fixture] of stated) {
      if (drivenApart.includes(name)) continue;
      const sidecar = name === 'receipt-tampered-v1' || name === 'receipt-meas-mismatch-v1' ? VALID : receiptJson(name);
      const result = runCli(
        argsFor({
          receipt: `${DATA}${fixture.path}`,
          requestDigest: sidecar.payload.req,
          responseDigest: sidecar.payload.res,
        }),
      );
      if (fixture.expected === 'verify-ok') {
        expect(result.status, name).toBe(0);
        expect(verdictOf(result).ok, name).toBe(true);
      } else {
        expect(result.status, name).toBe(1);
        expect(verdictOf(result).code, name).toBe(fixture.expected);
      }
    }
  });

  it('refuses a receipt whose measurement is not the one the policy pins', () => {
    const policy = policyFile({ measurements: { [SOFTWARE.payload.meas.tee]: [WRONG_SOFTWARE] } });
    const result = runCli(argsFor({ receipt: receiptPath('receipt-software-v1'), policy }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('MEASUREMENT_NOT_ALLOWED');
  });

  it('refuses a receipt from an issuer the policy does not pin', () => {
    const result = runCli(argsFor({ policy: policyFile({ issuers: ['dpl-deadbeef'] }) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('ISSUER_NOT_ALLOWED');
  });

  it('refuses a receipt from an instance the policy does not pin', () => {
    const result = runCli(argsFor({ policy: policyFile({ instances: ['cvm-i-deadbeef'] }) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('INSTANCE_NOT_ALLOWED');
  });

  it('refuses a key the policy pins but the manifest does not declare', () => {
    const other = { kid: 'f'.repeat(64), alg: 'Ed25519', publicKey: PUBLIC_KEY };
    const result = runCli(argsFor({ manifest: manifestFile({ keys: [other] }) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('MANIFEST_KEY_NOT_PINNED');
  });

  it('refuses a manifest whose declared key is not the key the policy pinned', () => {
    const result = runCli(argsFor({ policy: policyFile({ keys: { [KID]: OTHER_KEY } }) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('MANIFEST_KEY_NOT_PINNED');
  });

  it('refuses a receipt signed with a key the policy names no pin for', () => {
    const result = runCli(argsFor({ policy: policyFile({ keys: { ['a'.repeat(64)]: PUBLIC_KEY } }) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('MANIFEST_KEY_NOT_PINNED');
  });

  it('refuses a manifest that is not a deployment manifest', () => {
    const result = runCli(argsFor({ manifest: written('manifest.json', JSON.stringify({ iss: ISSUER })) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('BAD_MANIFEST');
  });

  it('refuses a receipt that answers a different challenge', () => {
    const result = runCli(argsFor({ nonce: '00112233445566778899aabbccddeeff' }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('NONCE_MISMATCH');
  });

  it('refuses a receipt whose request digest is not the one handed over', () => {
    const result = runCli(argsFor({ requestDigest: '0'.repeat(64) }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('REQUEST_HASH_MISMATCH');
  });

  it('refuses a receipt the policy window has closed on, and closes on the clock it was given', () => {
    const late = new Date((VALID.payload.iat + 3600) * 1000).toISOString();
    const result = runCli(argsFor({ now: late }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('STALE_RECEIPT');
  });

  it('refuses bytes that are not a receipt at all', () => {
    const notAReceipt = written('not-a-receipt.bin', 'these are not a COSE_Sign1 structure');
    const result = runCli(argsFor({ receipt: notAReceipt }));
    expect(result.status).toBe(1);
    expect(verdictOf(result).code).toBe('MALFORMED_CBOR');
  });

  it('refuses a policy that pins nothing as an input error, not a verdict', () => {
    const empty = written('empty-policy.json', JSON.stringify({ v: 1 }));
    const result = runCli(argsFor({ policy: empty, json: false }));
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('POLICY_NOTHING_PINNED');
  });

  it('asks for the flags that decide the verdict before it reads a receipt', () => {
    const receipt = receiptPath('receipt-valid-v1');
    const noPolicy = runCli(['verify-receipt', receipt, '--manifest', manifestFile(), '--nonce', NONCE]);
    expect(noPolicy.status).toBe(2);
    expect(noPolicy.stderr).toContain('--policy is required');

    const noManifest = runCli(['verify-receipt', receipt, '--policy', policyFile(), '--nonce', NONCE]);
    expect(noManifest.status).toBe(2);
    expect(noManifest.stderr).toContain('--manifest is required');

    const noNonce = runCli(['verify-receipt', receipt, '--policy', policyFile(), '--manifest', manifestFile()]);
    expect(noNonce.status).toBe(2);
    expect(noNonce.stderr).toContain('--nonce is required');
  });

  it('asks for a digest or the bytes on each side of the conversation', () => {
    const noRequest = runCli([
      'verify-receipt', receiptPath('receipt-valid-v1'), '--policy', policyFile(), '--manifest', manifestFile(),
      '--nonce', NONCE, '--response-hash', RESPONSE_DIGEST,
    ]);
    expect(noRequest.status).toBe(2);
    expect(noRequest.stderr).toContain('one of --request-body or --request-hash is required');

    const noResponse = runCli([
      'verify-receipt', receiptPath('receipt-valid-v1'), '--policy', policyFile(), '--manifest', manifestFile(),
      '--nonce', NONCE, '--request-hash', REQUEST_DIGEST,
    ]);
    expect(noResponse.status).toBe(2);
    expect(noResponse.stderr).toContain('one of --response-body or --response-hash is required');
  });

  it('hashes the bytes it was handed rather than trusting a written digest', () => {
    const requestBody = written('request-body.json', '{"model":"some other request"}');
    const result = runCli(argsFor({ requestBody, json: false }));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('REQUEST_HASH_MISMATCH');
    expect(result.stderr).toContain('the request that was sent');
  });

  it('refuses a hex argument that is not whole bytes or not the width it names', () => {
    const narrowDigest = runCli(argsFor({ requestDigest: 'abcd' }));
    expect(narrowDigest.status).toBe(2);
    expect(narrowDigest.stderr).toContain('--request-hash must be 64 hex digits');

    const notHex = runCli(argsFor({ requestDigest: 'zz' }));
    expect(notHex.status).toBe(2);
    expect(notHex.stderr).toContain('--request-hash must be a hex string of whole bytes');

    const oddNonce = runCli(argsFor({ nonce: 'abc' }));
    expect(oddNonce.status).toBe(2);
    expect(oddNonce.stderr).toContain('--nonce must be a hex string of whole bytes');
  });

  it('refuses an unreadable receipt path and a second positional', () => {
    const missing = runCli(argsFor({ receipt: join(tempDir, 'nope.cbor') }));
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain('cannot read receipt');

    const tooMany = runCli(['verify-receipt', 'a.cbor', 'b.cbor']);
    expect(tooMany.status).toBe(2);
    expect(tooMany.stderr).toContain("expected exactly one argument: 'verify-receipt <receipt>'");
  });

  it('adds no exit code to the ones the tool already uses', () => {
    const verified = runCli(argsFor({})).status;
    const refused = runCli(argsFor({ nonce: '00112233445566778899aabbccddeeff' })).status;
    const usage = runCli(['verify-receipt']).status;
    expect([verified, refused, usage]).toEqual([0, 1, 2]);
  });

  it('names the command in help and in the unknown-command refusal', () => {
    const help = runCli(['--help']);
    expect(help.stdout).toContain('ashaveri verify-receipt <receipt>');
    expect(help.stdout).toContain('--response-body <file>');
    expect(help.stdout).toContain('--manifest <file>');
    const unknown = runCli(['frobnicate']);
    expect(unknown.status).toBe(2);
    expect(unknown.stderr).toContain('verify-receipt');
  });
});
