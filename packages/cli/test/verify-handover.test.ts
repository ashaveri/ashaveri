import { createHash, createPrivateKey, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  DEPLOYMENT_MANIFEST_CONTENT_TYPE,
  EXPORT_CONTENT_TYPE,
  PACK_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  REDACTION_CONTENT_TYPE,
  decodeCanonical,
  encodeCanonical,
  encodeExportProtectedHeader,
  generateSigningKey,
  packRecordDigest,
  packSigStructure,
  sealDeploymentManifest,
  sealExport,
  signingKeyFromSeed,
  toHex,
  type SigningKey,
} from '@ashaveri/receipt';
import { ATTESTED_MARKING, stampedReceiptBytes } from './stamped-receipt.js';

/**
 * `ashaveri verify-handover`, run over bytes of every signed shape it can meet.
 *
 * The documents are not built to this file's own idea of what they are: the receipts and the exports
 * are the published fixtures, the pack is framed by the format package's own `packSigStructure` and
 * `packRecordDigest` over the published receipts, and the manifest is sealed by the shipped sealer. The
 * only hand-written thing here is the framing a published pack document needs because the package
 * publishes a pack reader and no pack writer, and that framing is checked by the shipped reader rather
 * than by an assertion in this file, which is the only proof worth having that a pack assembled outside
 * the package is a pack the package reads.
 *
 * What is asserted is the separation the five content types exist to draw, visible at the command edge:
 * the type found is printed before anything about validity, a document is read by the reader for its
 * own type, and a header changed without a new signature is answered by the signature rather than by a
 * verdict about the shape it now claims to be.
 *
 * The two pinned verbs, `ashaveri verify-pack` and `ashaveri verify-export`, are tested here rather than
 * in files of their own because they are this runner with the answer in label 3 fixed to one value, and
 * the two claims worth making about that are both comparisons against this command's own answers: the
 * reading of a document of the pinned type is one report and not a second one shaped like the first, and
 * a document of another type meets the refusal this command already gives a type it holds no reader for.
 * The documents are the same bytes either way, which is the only reason the comparison can be made.
 *
 * One shape arrives with a second document. An amendment is checked against the pack it designates by a
 * digest, so its cases hand that pack in through `--companion`, and the whole published redaction suite is
 * replayed through the command path here rather than only through the library. The rows this path answers
 * otherwise are not named by a table in this file: each row states its own answer, with the code and the exit
 * beside it where they differ from the library's, and what is checked here is that a run agrees with the file.
 *
 * No case here needs a longer timeout than the runner's default: the slowest measured case without a stated
 * window is the one that checks a key's canonical spelling, at 1,043 ms over four CLI invocations with three
 * test files running at once, and each invocation signs or verifies a handful of Ed25519 signatures rather
 * than a loop of them. Four cases run the CLI far more than four times and carry a stated window chosen from
 * what each measures, with the figures beside them; the widest is the 43-row replay below.
 */

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DATA = fileURLToPath(new URL('../../fixtures/data/', import.meta.url));

const tempDir = mkdtempSync(join(tmpdir(), 'ashaveri-verify-handover-'));
afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

interface CliResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(args: string[], cwd?: string): CliResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 15_000,
    killSignal: 'SIGKILL',
    ...(cwd === undefined ? {} : { cwd }),
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

/**
 * One file kept under its own name, in a directory of its own.
 *
 * An export item names its original by that name and by nothing else, so a counter prefix on the file
 * would be a different file as far as the document is concerned. The directory keeps the names unique
 * without changing either of them.
 */
function writtenUnderItsOwnName(name: string, data: Uint8Array): string {
  const directory = join(tempDir, `dir${writtenCount++}`);
  mkdirSync(directory, { recursive: true });
  const path = join(directory, name);
  writeFileSync(path, data);
  return path;
}

function verdictOf(result: CliResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

/** The receipt signing key the published fixtures are issued under, and its key in the bytes they carry. */
const RECEIPT_KEY = JSON.parse(readFileSync(`${DATA}keys/receipt-key-v1.json`, 'utf8')) as {
  kid: string;
  publicKey: string;
  privateKey: string;
};

/** An Ed25519 signature over arbitrary bytes, from the published seed, for the pack framing below. */
function signWithSeed(seedHex: string, message: Uint8Array): Uint8Array {
  const key = createPrivateKey({
    // The PKCS8 wrapping of an Ed25519 private key: an algorithm identifier and the seed inside an
    // octet string, which is how node takes a raw 32-byte seed.
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  return new Uint8Array(sign(null, message, key));
}

function base64UrlOfHex(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * A spelling of a canonical key that decodes to its bytes without being what any encoder writes.
 *
 * The last character of a 43-character encoding carries two bits an encoder never sets, so the other
 * three alphabet positions in its group of four decode to the same 32 bytes. That is the spelling the
 * key designation refuses, because a designation accepted in it would be a key whose id is right and
 * whose text is the one no other reader writes.
 */
function nonCanonicalSpelling(value: string): string {
  const last = BASE64URL_ALPHABET.indexOf(value.charAt(value.length - 1));
  const neighbour = last % 4 === 3 ? last - 1 : last + 1;
  return `${value.slice(0, -1)}${BASE64URL_ALPHABET[neighbour]}`;
}

const RECEIPT_PUBLIC_B64URL = base64UrlOfHex(RECEIPT_KEY.publicKey);
const RECEIPT_PATH = `${DATA}receipts/receipt-valid-v1.cbor`;
const SOFTWARE_RECEIPT_PATH = `${DATA}receipts/receipt-software-v1.cbor`;

function receiptStampOf(path: string): number {
  const json = JSON.parse(readFileSync(path.replace('.cbor', '.json'), 'utf8')) as { payload: { iat: number } };
  return json.payload.iat;
}

/**
 * A pack over two published receipts, framed by the format package's own rules.
 *
 * `pack.cddl` is written to be read and the package publishes a reader, `packSigStructure` and
 * `packRecordDigest`, but no writer, so the container is assembled here from those published pieces:
 * the record digests the chain is made of, the `Sig_structure` the signature covers, the header that
 * carries the pack's content type. Every field the reader checks for contradictions, the span around the
 * stamps, `at` after the span closes, the revision before the reads, `held` covering the oldest receipt,
 * is computed rather than guessed, and the shipped reader's acceptance is what says so.
 */
function packDocument(key: SigningKey, ids: readonly string[], movedStamp?: number): Uint8Array {
  const anchor = new Uint8Array(32);
  // The stamps the records are chained under, which the span then bounds. Moving one leaves a manifest
  // that is whole by its own lights, so the only thing a reader can find is that the receipt inside the
  // record attests a different instant than the frame it was chained in.
  const stamps = ids.map((one) => receiptStampOf(one)).map((one, index) => (index === movedStamp ? one + 60 : one));
  const from = Math.min(...stamps);
  const to = Math.max(...stamps) + 1;
  const at = to + 1_000;
  let previous: Uint8Array<ArrayBufferLike> = anchor;
  const items: Map<string, unknown>[] = [];
  for (const [index, one] of ids.entries()) {
    const receipt = new Uint8Array(readFileSync(one));
    const stamp = stamps[index] as number;
    const item = new Map<string, unknown>([
      ['id', `receipt-${String(index)}`],
      ['iat', stamp],
      ['prev', previous],
      ['receipt', receipt],
    ]);
    previous = packRecordDigest({ id: `receipt-${String(index)}`, iat: stamp, prev: previous, receipt });
    items.push(item);
  }
  const manifest = new Map<string, unknown>([
    ['v', 2],
    ['at', at],
    ['span', new Map([['from', from], ['to', to]])],
    ['chain', new Map([['anchor', anchor], ['head', previous]])],
    ['duty', new Map<string, unknown>([['art', 'retention-evidence'], ['rev', at - 10], ['required', 31_536_000], ['held', at - from]])],
    ['items', items],
    ['carried', []],
  ]);
  const payloadBytes = encodeCanonical(manifest);
  const protectedBytes = encodeExportProtectedHeader(key.kid, PACK_CONTENT_TYPE);
  const signature = signWithSeed(Buffer.from(key.privateKey).toString('hex'), packSigStructure(protectedBytes, payloadBytes));
  return sealExport(protectedBytes, payloadBytes, signature);
}

/** The published pack fixture's key, which is the key every export vector is signed under. */
const EXPORT_FIXTURE = JSON.parse(readFileSync(`${DATA}export-v1.json`, 'utf8')) as {
  layout: { key: { publicKeyHex: string }; vectors?: never };
  vectors: { name: string; documentBase64Url: string; read: { companions?: { name: string; bytesBase64Url: string }[] } }[];
};
const EXPORT_KEY_B64URL = base64UrlOfHex(EXPORT_FIXTURE.layout.key.publicKeyHex);

function exportVector(name: string): { bytes: Uint8Array; companions: { name: string; bytes: Uint8Array }[] } {
  const vector = EXPORT_FIXTURE.vectors.find((one) => one.name === name);
  if (vector === undefined) {
    throw new Error(`the published export suite has no vector named '${name}'`);
  }
  return {
    bytes: Buffer.from(vector.documentBase64Url, 'base64url'),
    companions: (vector.read.companions ?? []).map((one) => ({ name: one.name, bytes: Buffer.from(one.bytesBase64Url, 'base64url') })),
  };
}

/**
 * One row of the published redaction suite, and one row of the published pack suite it names.
 *
 * The amendment arrives with the pack it speaks about, because the format designates that pack by a digest
 * of its whole bytes: the rows carry both documents, and the key the row states is the one the pack suite
 * seals that pack with. So every claim below is read out of published material rather than out of a document
 * this file assembled to agree with the reader.
 */
interface PublishedRedactionRow {
  readonly name: string;
  readonly documentBase64Url: string;
  readonly packBase64Url?: string;
  readonly read: { readonly pinned?: string; readonly retained?: readonly { kid: string; publicKeyBase64Url: string }[] };
  readonly verdict: string;
  /**
   * What this command path answers for the row's pair: `null` where it answers exactly what `verdict` states,
   * and the code and the exit beside it where it reaches the same fact one step earlier than the reader does.
   * The suite carries this table, states the member on every row, and this file reads it rather than keeping one
   * of its own; the presence assertion belongs to `packages/fixtures/test/redaction-vectors.test.ts`.
   */
  readonly command: { readonly code: string; readonly exit: number } | null;
  readonly survivors?: string[];
  readonly reducedHex?: string;
  readonly originalHeadHex?: string;
}

interface PublishedPackRow {
  readonly name: string;
  readonly documentBase64Url: string;
  readonly read: { readonly pinned?: string };
}

const REDACTION_FIXTURE = JSON.parse(readFileSync(`${DATA}redaction-v1.json`, 'utf8')) as { vectors: PublishedRedactionRow[] };
const PACK_FIXTURE = JSON.parse(readFileSync(`${DATA}pack-v1.json`, 'utf8')) as { vectors: PublishedPackRow[] };

function redactionRow(name: string): PublishedRedactionRow {
  const row = REDACTION_FIXTURE.vectors.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published redaction suite has no vector named '${name}'`);
  }
  return row;
}

function packRow(name: string): PublishedPackRow {
  const row = PACK_FIXTURE.vectors.find((one) => one.name === name);
  if (row === undefined) {
    throw new Error(`the published pack suite has no vector named '${name}'`);
  }
  return row;
}

/** A deployment manifest in the shape the SDK parses, sealed as a deployment that was handed an identity serves it. */
const SEALING_KEY = generateSigningKey();
const STRANGER_KEY = generateSigningKey();

function manifestDocument(): string {
  const receipt = JSON.parse(readFileSync(`${DATA}receipts/receipt-valid-v1.json`, 'utf8')) as {
    payload: { iss: string; ins: string; mdl: string; wts: string; epk: number; meas: { tee: string; m: string } };
  };
  return JSON.stringify({
    v: 1,
    iss: receipt.payload.iss,
    ins: receipt.payload.ins,
    epk: receipt.payload.epk,
    keys: [{ kid: RECEIPT_KEY.kid, alg: 'Ed25519', publicKey: RECEIPT_PUBLIC_B64URL }],
    models: [{ id: receipt.payload.mdl, wts: receipt.payload.wts }],
    meas: { tee: receipt.payload.meas.tee, m: receipt.payload.meas.m },
  });
}

/**
 * The same receipt bytes, with the content type in the protected header changed and nothing else.
 *
 * The framing helpers a published export vector is assembled with do the work: the new header is the
 * canonical map the format writes, the envelope is the tagged four elements, and the payload and the
 * signature are lifted out of the fixture untouched. So the only difference between these bytes and the
 * published receipt is the claim in label 3, which is exactly the claim a reader must not believe
 * without the signature that covers it.
 */
function relabelledReceipt(contentType: string): Uint8Array {
  const bytes = new Uint8Array(readFileSync(RECEIPT_PATH));
  const envelope = decodeCanonical(bytes) as { contents: readonly unknown[] };
  const [protectedBytes, , payloadBytes, signature] = envelope.contents as [Uint8Array, Map<unknown, unknown>, Uint8Array, Uint8Array];
  const header = decodeCanonical(protectedBytes) as Map<unknown, unknown>;
  const kid = header.get(4);
  if (!(kid instanceof Uint8Array)) {
    throw new Error('the published receipt carries no kid to reuse');
  }
  return sealExport(encodeExportProtectedHeader(kid, contentType), payloadBytes, signature);
}

/** A `COSE_Sign1` carrying a content type no format publishes, correctly signed. */
function unknownTypeDocument(contentType: string): Uint8Array {
  const key = signingKeyFromSeed(Buffer.from(RECEIPT_KEY.privateKey, 'hex'));
  const protectedBytes = encodeExportProtectedHeader(key.kid, contentType);
  const payloadBytes = encodeCanonical(new Map([['nothing', 'a document of a shape nothing publishes']]));
  const signature = signWithSeed(Buffer.from(key.privateKey).toString('hex'), packSigStructure(protectedBytes, payloadBytes));
  return sealExport(protectedBytes, payloadBytes, signature);
}

describe('ashaveri verify-handover', () => {
  it('reports the region a hand-built receipt names, and the one the plain fixture names', () => {
    // What this row prints is the payload's own statement about one region of the response, so what the
    // test holds is the member and not a version beside it. A report that printed nothing for a receipt
    // naming a region would be a false sentence in the one report whose promise is that it prints what the
    // document says. The two published shapes are read by this command's own reader, which takes no
    // response bytes and so runs no marking check: the row below reports the claim, not a verdict on it.
    const stamped = written('stamped.cbor', stampedReceiptBytes(ATTESTED_MARKING));
    const human = runCli(['verify-handover', stamped, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain('payload:          v1');
    expect(human.stdout).toContain(`marked region:    ${toHex(ATTESTED_MARKING.d)} (${ATTESTED_MARKING.sch})`);
    const json = verdictOf(runCli(['verify-handover', stamped, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    expect((json.document as Record<string, unknown>).markedRegion).toEqual({
      scheme: ATTESTED_MARKING.sch,
      sha256: toHex(ATTESTED_MARKING.d),
    });

    const plain = JSON.parse(readFileSync(`${DATA}receipts/receipt-valid-v1.json`, 'utf8')) as {
      payload: { mk: { sch: string; d: string } };
    };
    const unmarked = runCli(['verify-handover', RECEIPT_PATH, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(unmarked.stdout).toContain(`marked region:    ${plain.payload.mk.d} (${plain.payload.mk.sch})`);
    expect(
      ((verdictOf(runCli(['verify-handover', RECEIPT_PATH, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json'])).document as Record<string, unknown>).markedRegion),
    ).toEqual({ scheme: plain.payload.mk.sch, sha256: plain.payload.mk.d });
  });

  it('states the region the published marked receipt names, in both renderings', () => {
    // The other marked shape, and the one published under this tree rather than written by a test: a row
    // that printed nothing for these bytes would be a false sentence in the report whose whole promise is
    // that it prints what the document says. The label and digest come from the fixture's own JSON twin, so
    // the assertion is against the published document rather than a copy of its contents made here.
    const marked = JSON.parse(readFileSync(`${DATA}receipts/receipt-marked-v1.json`, 'utf8')) as {
      payload: { mk: { sch: string; d: string } };
    };
    const path = `${DATA}receipts/receipt-marked-v1.cbor`;
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    expect(human.stdout).toContain('payload:          v1');
    expect(human.stdout).toContain(`marked region:    ${marked.payload.mk.d} (${marked.payload.mk.sch})`);
    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    expect((json.document as Record<string, unknown>).markedRegion).toEqual({
      scheme: marked.payload.mk.sch,
      sha256: marked.payload.mk.d,
    });
  });

  it('names a published receipt as a receipt, before it says anything about validity', () => {
    const human = runCli(['verify-handover', RECEIPT_PATH, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stderr).toBe('');
    expect(human.status).toBe(0);
    const lines = human.stdout.split('\n');
    expect(lines[0]).toBe('content type:     ashaveri/receipt');
    const typeLine = human.stdout.indexOf('content type:');
    expect(typeLine).toBeGreaterThanOrEqual(0);
    expect(typeLine).toBeLessThan(human.stdout.indexOf('signature:'));
    expect(human.stdout).toContain('the nonce against a challenge');
    expect(human.stdout).toContain('verify-receipt');

    const json = verdictOf(runCli(['verify-handover', RECEIPT_PATH, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe('ashaveri/receipt');
    expect(json.reader).toBe('verifyReceipt');
    expect(json.kid).toBe(RECEIPT_KEY.kid);
    expect((json.document as Record<string, unknown>).signature).toBe(true);
    expect(json.notChecked).toBeInstanceOf(Array);
  });

  it('names a published export as an export and checks its original', () => {
    const document = exportVector('well-formed-plain');
    const path = written('export-plain.cbor', document.bytes);
    const json = verdictOf(runCli(['verify-handover', path, `--key=${EXPORT_KEY_B64URL}`, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe(EXPORT_CONTENT_TYPE);
    expect(json.reader).toBe('verifyExport');
    const body = json.document as Record<string, unknown>;
    expect(body.signature).toBe(true);
    expect((body.collection as Record<string, unknown>).kind).toBe('plain');
    expect((body.originals as unknown[]).length).toBe(1);
  });

  it('names a sealed deployment manifest as a manifest and says whose seal it checked', () => {
    const path = written('manifest.cbor', Buffer.from(sealDeploymentManifest(new TextEncoder().encode(manifestDocument()), SEALING_KEY)));
    const designated = Buffer.from(SEALING_KEY.publicKey).toString('base64url');
    const json = verdictOf(runCli(['verify-handover', path, `--manifest-key=${designated}`, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe('ashaveri/deployment-manifest');
    const seal = (json.document as { seal: { authenticated: unknown; kid: unknown } }).seal;
    expect(seal.authenticated).toBe(true);
    expect(seal.kid).toBe(toHex(SEALING_KEY.kid));
    const human = runCli(['verify-handover', path, `--manifest-key=${designated}`]);
    expect(human.stdout).toContain('the seal holds under');
    expect(human.stdout).toContain('--manifest-key');
  });

  it('refuses a manifest sealed under a key this run did not designate, as a refusal about the call', () => {
    const path = written('manifest-stranger.cbor', Buffer.from(sealDeploymentManifest(new TextEncoder().encode(manifestDocument()), STRANGER_KEY)));
    const designated = Buffer.from(SEALING_KEY.publicKey).toString('base64url');
    const result = runCli(['verify-handover', path, `--manifest-key=${designated}`, '--json']);
    expect(result.status).toBe(1);
    expect(verdictOf(result)).toMatchObject({ ok: false, contentType: 'ashaveri/deployment-manifest', code: 'MANIFEST_NOT_AUTHENTICATED' });
  });

  it('reports a pack over published receipts, walked from the anchor to the head', () => {
    const key = signingKeyFromSeed(Buffer.from(RECEIPT_KEY.privateKey, 'hex'));
    const path = written('pack.cbor', Buffer.from(packDocument(key, [RECEIPT_PATH, SOFTWARE_RECEIPT_PATH])));
    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe(PACK_CONTENT_TYPE);
    expect(json.reader).toBe('verifyPack');
    const body = json.document as Record<string, unknown>;
    expect(body.walked).toEqual({ walked: 2, declared: 2 });
    expect((body.items as unknown[]).length).toBe(2);
    expect(body.duty).toEqual({ art: 'retention-evidence', rev: expect.any(Number), required: 31_536_000, held: expect.any(Number) });

    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.stdout).toContain('judges neither');
  });

  it('refuses a pack whose own original attests a different instant than the record chains it', () => {
    const key = signingKeyFromSeed(Buffer.from(RECEIPT_KEY.privateKey, 'hex'));
    const path = written('pack-moved-stamp.cbor', Buffer.from(packDocument(key, [RECEIPT_PATH, SOFTWARE_RECEIPT_PATH], 1)));
    const result = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.contentType).toBe(PACK_CONTENT_TYPE);
    expect(refusal.code).toBe('PACK_RECEIPT_STAMP_MISMATCH');
    expect(String(refusal.message)).toContain('receipt-1');
  });

  it('refuses a pack whose kid no designation reaches, which is the call rather than the document', () => {
    const key = signingKeyFromSeed(Buffer.from(RECEIPT_KEY.privateKey, 'hex'));
    const path = written('pack-unknown-key.cbor', Buffer.from(packDocument(key, [RECEIPT_PATH])));
    const stranger = Buffer.from(STRANGER_KEY.publicKey).toString('base64url');
    const result = runCli(['verify-handover', path, `--key=${stranger}`, '--json']);
    expect(result.status).toBe(1);
    expect(verdictOf(result)).toMatchObject({ ok: false, contentType: PACK_CONTENT_TYPE, code: 'PACK_UNKNOWN_KEY' });
  });

  it('refuses an export item whose companion file was not handed, and passes when it is', () => {
    const document = exportVector('companion-handed-and-checked');
    const path = written('export-companion.cbor', document.bytes);
    const missing = runCli(['verify-handover', path, `--key=${EXPORT_KEY_B64URL}`, '--json']);
    expect(missing.status).toBe(1);
    expect(verdictOf(missing)).toMatchObject({ ok: false, contentType: EXPORT_CONTENT_TYPE, code: 'EXPORT_ORIGINAL_UNAVAILABLE' });
    expect(String(verdictOf(missing).message)).toContain('contract.pdf');

    const companionPath = writtenUnderItsOwnName(document.companions[0]?.name ?? 'companion', document.companions[0]?.bytes ?? new Uint8Array());
    const handed = runCli(['verify-handover', path, `--key=${EXPORT_KEY_B64URL}`, `--companion=${companionPath}`, '--json']);
    expect(handed.stderr).toBe('');
    expect(handed.status).toBe(0);
    expect(verdictOf(handed).ok).toBe(true);
  });

  it('answers a receipt relabelled as a pack with a signature failure, not with a pack verdict', () => {
    const path = written('relabelled.cbor', Buffer.from(relabelledReceipt(PACK_CONTENT_TYPE)));
    const human = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.status).toBe(1);
    expect(human.stdout).toBe('');
    expect(human.stderr.indexOf(PACK_CONTENT_TYPE)).toBeLessThan(human.stderr.indexOf('verification failed'));
    expect(human.stderr).toContain('(INVALID_SIGNATURE)');
    expect(human.stderr).not.toMatch(/walked|span|duty/);

    const json = verdictOf(runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']));
    expect(json).toMatchObject({ ok: false, contentType: PACK_CONTENT_TYPE, code: 'INVALID_SIGNATURE' });
  });

  it('refuses a content type no format publishes and names the one it met', () => {
    const path = written('future.cbor', Buffer.from(unknownTypeDocument('ashaveri/telemetry')));
    const result = runCli(['verify-handover', path, `--key=${RECEIPT_PUBLIC_B64URL}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal.code).toBe('BAD_PROTECTED_HEADER');
    expect(String(refusal.message)).toContain('typ=ashaveri/telemetry');
    expect(refusal.contentType).toBeUndefined();
  });

  it('refuses an export wearing a receipt header as the receipt it claims to be', () => {
    const path = written('export-in-receipt-clothing.cbor', exportVector('wrong-content-type').bytes);
    const result = runCli(['verify-handover', path, `--key=${EXPORT_KEY_B64URL}`, '--json']);
    expect(result.status).toBe(1);
    expect(verdictOf(result)).toMatchObject({ ok: false, contentType: 'ashaveri/receipt', code: 'BAD_PAYLOAD' });
  });

  it('refuses an unsigned deployment manifest by saying that it is unsigned', () => {
    const path = written('manifest.json', manifestDocument());
    const result = runCli(['verify-handover', path]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('no COSE protected header to classify');
    expect(result.stderr).toContain('verify-receipt --manifest');
  });

  it('refuses a directory with the reason, and says that a pack is readable', () => {
    const bundle = join(tempDir, 'bundle');
    mkdirSync(bundle, { recursive: true });
    writeFileSync(join(bundle, 'receipt.cbor'), readFileSync(RECEIPT_PATH));
    const result = runCli(['verify-handover', bundle]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('is a directory');
    expect(result.stderr).toContain('one signed document per run');
    expect(result.stderr).toContain('pack');
  });

  it('asks for the key a signed document needs, by the type it found', () => {
    const result = runCli(['verify-handover', RECEIPT_PATH]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--key is required to verify ashaveri/receipt');
  });

  it('reports a designation the document in front of it did not consult', () => {
    const path = written('manifest-both.cbor', Buffer.from(sealDeploymentManifest(new TextEncoder().encode(manifestDocument()), SEALING_KEY)));
    const designated = Buffer.from(SEALING_KEY.publicKey).toString('base64url');
    const result = runCli(['verify-handover', path, `--manifest-key=${designated}`, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(new RegExp(`not consulted: +${RECEIPT_KEY.kid}`));
    expect(result.stdout).toContain('is not authenticated by it');
  });

  it('refuses a document argument that is not one argument, and a key that is not a key', () => {
    expect(runCli(['verify-handover', 'a.cbor', 'b.cbor']).stderr).toContain("expected exactly one argument: 'verify-handover <document>'");
    expect(runCli(['verify-handover']).status).toBe(2);
    const shortKey = runCli(['verify-handover', RECEIPT_PATH, '--key=short']);
    expect(shortKey.status).toBe(2);
    expect(shortKey.stderr).toContain('--key must be the base64url of 32 bytes');
    const nonCanonical = runCli(['verify-handover', RECEIPT_PATH, `--key=${nonCanonicalSpelling(RECEIPT_PUBLIC_B64URL)}`]);
    expect(nonCanonical.status).toBe(2);
    expect(nonCanonical.stderr).toContain('canonical base64url spelling');
  });

  it('reads the document from stdin as readily as from a name', () => {
    const pipe = spawnSync(process.execPath, [CLI, 'verify-handover', '-', `--key=${RECEIPT_PUBLIC_B64URL}`, '--json'], {
      input: readFileSync(RECEIPT_PATH),
      encoding: 'utf8',
      timeout: 15_000,
    });
    expect(pipe.status).toBe(0);
    expect(JSON.parse(pipe.stdout).contentType).toBe('ashaveri/receipt');
  });
});

/** A published field this file cannot do without, refused by name rather than defaulted to an empty frame. */
function published(value: string | undefined, what: string): string {
  if (value === undefined) {
    throw new Error(`the published suite states no ${what}, so this file would be asserting about nothing`);
  }
  return value;
}

/**
 * One published amendment, the pack it designates, and the pack document itself, as three files, plus the
 * key the suite states its caller holds. The amendment and the pack are sealed by one key, which is the key
 * the pack suite seals that pack with, so the same designation answers both documents.
 */
const AMENDMENT = redactionRow('removed-middle-record');
const AMENDMENT_PATH = written('amendment.cbor', Buffer.from(published(AMENDMENT.documentBase64Url, 'amendment document'), 'base64url'));
const AMENDMENT_PACK_PATH = written('amendment-pack.cbor', Buffer.from(published(AMENDMENT.packBase64Url, 'pack the amendment designates'), 'base64url'));
const AMENDMENT_KEY = `--key=${published(AMENDMENT.read.pinned, 'pinned key')}`;
const PACK_DOCUMENT_PATH = written(
  'published-pack.cbor',
  Buffer.from(published(packRow('well-formed-three-items').documentBase64Url, 'pack document'), 'base64url'),
);

/** What one command run answered: the published verdict's shape, or the fact that it refused the call. */
function replayedVerdict(result: CliResult): string {
  if (result.status === 2) return 'usage';
  try {
    const report = JSON.parse(result.stdout) as { ok?: boolean; code?: string };
    return report.ok === true ? 'verify-ok' : published(report.code, 'refusal code');
  } catch {
    return 'unreadable';
  }
}

/** The window for the 43-run case below: measured at 9,158 ms over 43 invocations on a warm host, and given eight times that room. */
const WHOLE_SUITE_THROUGH_THE_COMMAND_PATH = { timeout: 80_000 };

describe('an excision amendment at the command edge', () => {
  it('reads an amendment against the pack it names, and keeps the two chain heads apart', () => {
    const json = verdictOf(runCli(['verify-handover', AMENDMENT_PATH, AMENDMENT_KEY, `--companion=${AMENDMENT_PACK_PATH}`, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe('ashaveri/redaction');
    expect(json.reader).toBe('verifyRedaction');
    const body = json.document as Record<string, unknown>;
    expect(body.signature).toBe(true);
    expect(body.survivors).toEqual({ survivors: 2, declared: 3 });
    expect((body.survivorItems as { id: string }[]).map((one) => one.id)).toEqual(AMENDMENT.survivors);
    // The published row states both heads, and they are never equal on an accepted row: the pack's signed
    // head holds over the pack's own run, and the survivor head is a chain that pack does not contain.
    expect(body.reduced).toBe(AMENDMENT.reducedHex);
    expect(body.originalHead).toBe(AMENDMENT.originalHeadHex);
    expect(body.reduced).not.toBe(body.originalHead);
    // The designation is the reader's hash of the bytes this run handed, and the pack reached this run under
    // a name no format reserves, because an amendment names its pack by a digest and not by a name.
    expect(body.pack).toEqual({ sha256: createHash('sha256').update(readFileSync(AMENDMENT_PACK_PATH)).digest('hex') });

    const human = runCli(['verify-handover', AMENDMENT_PATH, AMENDMENT_KEY, `--companion=${AMENDMENT_PACK_PATH}`]);
    expect(human.status).toBe(0);
    expect(human.stdout.split('\n')[0]).toBe('content type:     ashaveri/redaction');
    expect(human.stdout).toContain('survivor chain head');
    expect(human.stdout).toContain("pack's own head");
    expect(human.stdout).toContain('unreachable anywhere this deployment still holds them');
  });

  it('refuses an amendment whose pack was not handed, naming the input the call left out', () => {
    const result = runCli(['verify-handover', AMENDMENT_PATH, AMENDMENT_KEY, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal).toMatchObject({ ok: false, contentType: 'ashaveri/redaction', code: 'REDACTION_PACK_UNAVAILABLE' });
    expect(String(refusal.message)).toContain('the pack it names');
  });

  it('refuses the bytes handed as the pack when an amendment designates another', () => {
    // The amendment's own document parked at the companion position is a pack to nobody: the designation is
    // recomputed from the bytes and compared before the pack is opened, which is the whole of this row.
    const result = runCli(['verify-handover', AMENDMENT_PATH, AMENDMENT_KEY, `--companion=${AMENDMENT_PATH}`, '--json']);
    expect(result.status).toBe(1);
    const refusal = verdictOf(result);
    expect(refusal).toMatchObject({ ok: false, contentType: 'ashaveri/redaction', code: 'REDACTION_PACK_MISMATCH' });
    expect(String(refusal.message)).toContain('redaction names pack=');
  });

  it('refuses a call that hands an amendment more than one pack', () => {
    const result = runCli(['verify-handover', AMENDMENT_PATH, AMENDMENT_KEY, `--companion=${AMENDMENT_PACK_PATH}`, `--companion=${PACK_DOCUMENT_PATH}`, '--json']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('an amendment is checked against one pack');
    expect(result.stdout).toBe('');
  });

  it('asks for the key an amendment needs by the type it found, which is the strict answer not the advisory one', () => {
    const result = runCli(['verify-handover', AMENDMENT_PATH, `--companion=${AMENDMENT_PACK_PATH}`]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--key is required to verify ashaveri/redaction');
  });

  it('reads a pack as a pack where a caller expected an amendment, and says so in the first line', () => {
    // The pair the other way round: the pack is the whole of an amendment's other document, so a pile read
    // with one command answers with the type inside the signature rather than with the caller's guess.
    const json = verdictOf(runCli(['verify-handover', PACK_DOCUMENT_PATH, AMENDMENT_KEY, `--companion=${AMENDMENT_PATH}`, '--json']));
    expect(json.ok).toBe(true);
    expect(json.contentType).toBe(PACK_CONTENT_TYPE);
    expect(json.reader).toBe('verifyPack');
  });

  it('replays every published redaction row through the command path', WHOLE_SUITE_THROUGH_THE_COMMAND_PATH, () => {
    expect(REDACTION_FIXTURE.vectors.length).toBeGreaterThanOrEqual(43);
    // The exception table is published with the rows: a row whose command answer is not its `verdict` states the
    // code and the exit in its `command` member, and every other row states null. Both lists below are names of
    // rows this loop ran, so neither can carry a note standing beside a case the suite no longer publishes, and
    // a suite that moves a row moves its exception with it.
    const recorded = REDACTION_FIXTURE.vectors.filter((row) => row.command !== null).map((row) => row.name);
    const diverged: string[] = [];
    const observed: string[] = [];
    for (const row of REDACTION_FIXTURE.vectors) {
      const args = ['verify-handover', written(`${row.name}.cbor`, Buffer.from(row.documentBase64Url, 'base64url')), '--json'];
      for (const key of row.read.pinned !== undefined ? [row.read.pinned] : (row.read.retained ?? []).map((one) => one.publicKeyBase64Url)) {
        args.push(`--key=${key}`);
      }
      if (row.packBase64Url !== undefined) {
        args.push(`--companion=${written(`${row.name}-pack.cbor`, Buffer.from(row.packBase64Url, 'base64url'))}`);
      }
      const result = runCli(args);
      const answer = replayedVerdict(result);
      const exception = row.command;
      // A row either answers what its published verdict states, or the published row states the code this path
      // answers and the exit it answers with. An unreadable run is neither, and fails here.
      expect(answer, `${row.name}: the command path answered something other than its published row states`).toBe(
        exception === null ? row.verdict : exception.code,
      );
      expect(result.status, `${row.name}: exit status beside the answer`).toBe(
        exception === null ? (row.verdict === 'verify-ok' ? 0 : 1) : exception.exit,
      );
      if (answer !== row.verdict) diverged.push(row.name);
      observed.push(`${row.name}: ${answer}`);
    }
    // The reverse check, read out of published data now rather than out of a table kept here. What only this line
    // can catch is the row whose published object states a divergence this run did not have, because its code
    // repeats its own `verdict`: the per-row expectation above passes on such a row, and a run that diverged
    // without a row recording it never reaches here, since it fails that expectation first. A published table
    // can only stay a source of facts rather than a mirror of the tool if this line is able to say so.
    expect(diverged.sort()).toEqual(recorded.sort());
    expect(observed.filter((one) => !one.endsWith('verify-ok')).length).toBeGreaterThanOrEqual(33);
  });
});

/**
 * The two verbs that pin label 3 to one value, run over the documents above.
 *
 * Nothing here builds a document of its own: every byte is one the handover cases already read, so the
 * two answers can be set against each other and a difference can only be the pin.
 */
describe('the pinned verbs verify-pack and verify-export', () => {
  const PACK_KEY = signingKeyFromSeed(Buffer.from(RECEIPT_KEY.privateKey, 'hex'));
  const packPath = written('pinned-pack.cbor', Buffer.from(packDocument(PACK_KEY, [RECEIPT_PATH, SOFTWARE_RECEIPT_PATH])));
  const exportPath = written('pinned-export.cbor', exportVector('well-formed-plain').bytes);
  const manifestBytes = sealDeploymentManifest(new TextEncoder().encode(manifestDocument()), SEALING_KEY);
  const manifestPath = written('pinned-manifest.cbor', Buffer.from(manifestBytes));
  const futurePath = written('pinned-future.cbor', Buffer.from(unknownTypeDocument('ashaveri/telemetry')));
  const manifestDesignation = `--manifest-key=${Buffer.from(SEALING_KEY.publicKey).toString('base64url')}`;

  /** One verb, the document it reads, and the designation that key is. */
  const own: Array<readonly [string, string, string, string]> = [
    ['verify-pack', packPath, `--key=${RECEIPT_PUBLIC_B64URL}`, PACK_CONTENT_TYPE],
    ['verify-export', exportPath, `--key=${EXPORT_KEY_B64URL}`, EXPORT_CONTENT_TYPE],
  ];

  /**
   * The window for the three cases below that run the CLI more than four times, chosen from what each of
   * them measures on a machine with a warm store: 1,274 ms over six invocations for the report
   * comparison, and 1,092 ms and 1,061 ms over six each for the two cross-type refusals, of which about
   * 180 ms per invocation is the cost of starting a `node` process rather than any crypto. The shared
   * Windows runner pays more for a process start than that, which is what makes a case at about two
   * seconds here a timeout risk there, and six times the slowest measurement leaves room without
   * hiding a case that genuinely hangs.
   */
  const MANY_CLI_RUNS = { timeout: 20_000 };

  it('gives its own type the same report the free verb gives, field for field', MANY_CLI_RUNS, () => {
    for (const [verb, path, designation, contentType] of own) {
      const pinned = runCli([verb, path, designation, '--json']);
      expect(pinned.status, verb).toBe(0);
      expect(pinned.stderr, verb).toBe('');
      const free = runCli(['verify-handover', path, designation, '--json']);
      expect(free.status, verb).toBe(0);
      // One report and not a second one shaped like the first. A pinned verb that added a field, dropped
      // one or worded one differently would be a second reader of the same bytes here.
      expect(JSON.parse(pinned.stdout), verb).toEqual(JSON.parse(free.stdout));
      expect(JSON.parse(pinned.stdout)).toMatchObject({ ok: true, contentType, reader: verb === 'verify-pack' ? 'verifyPack' : 'verifyExport' });
      const human = runCli([verb, path, designation]);
      expect(human.status, verb).toBe(0);
      expect(human.stdout, verb).toContain(`content type:     ${contentType}`);
    }
  });

  it('refuses every document that is not a pack, with the refusal the free verb gives', MANY_CLI_RUNS, () => {
    for (const [path, designation, contentType] of [
      [exportPath, `--key=${EXPORT_KEY_B64URL}`, EXPORT_CONTENT_TYPE],
      [RECEIPT_PATH, `--key=${RECEIPT_PUBLIC_B64URL}`, RECEIPT_CONTENT_TYPE],
      [manifestPath, manifestDesignation, DEPLOYMENT_MANIFEST_CONTENT_TYPE],
      // An amendment is refused here before its pack is asked for: the type is settled first, and a verb
      // that reads packs has no reader to hand those bytes to.
      [AMENDMENT_PATH, AMENDMENT_KEY, REDACTION_CONTENT_TYPE],
      [futurePath, `--key=${RECEIPT_PUBLIC_B64URL}`, 'ashaveri/telemetry'],
    ] as Array<readonly [string, string, string]>) {
      const json = runCli(['verify-pack', path, designation, '--json']);
      expect(json.status, contentType).toBe(1);
      const refusal = verdictOf(json);
      expect(refusal, contentType).toMatchObject({ ok: false, code: 'BAD_PROTECTED_HEADER' });
      // The refusal this command already gives, wording and all: one code's sentence about a content type
      // it holds no reader for, naming the type the header carries.
      expect(String(refusal.message), contentType).toContain(`typ=${contentType}`);
      // Nothing about the wrong document is reported, and no reader ran: the type is answered before a
      // designation is reached, which is why the pack codes cannot be what a caller hears here.
      expect(refusal.contentType, contentType).toBeUndefined();
      expect(refusal.document, contentType).toBeUndefined();
    }
    const human = runCli(['verify-pack', exportPath, `--key=${EXPORT_KEY_B64URL}`]);
    expect(human.status).toBe(1);
    expect(human.stdout).toBe('');
    expect(human.stderr).toContain('verification failed (BAD_PROTECTED_HEADER): ');
    expect(human.stderr).toContain(`typ=${EXPORT_CONTENT_TYPE}`);
  });

  it('refuses every document that is not an export, with the refusal the free verb gives', MANY_CLI_RUNS, () => {
    for (const [path, designation, contentType] of [
      [packPath, `--key=${RECEIPT_PUBLIC_B64URL}`, PACK_CONTENT_TYPE],
      [RECEIPT_PATH, `--key=${RECEIPT_PUBLIC_B64URL}`, RECEIPT_CONTENT_TYPE],
      [manifestPath, manifestDesignation, DEPLOYMENT_MANIFEST_CONTENT_TYPE],
      [AMENDMENT_PATH, AMENDMENT_KEY, REDACTION_CONTENT_TYPE],
      [futurePath, `--key=${RECEIPT_PUBLIC_B64URL}`, 'ashaveri/telemetry'],
    ] as Array<readonly [string, string, string]>) {
      const json = runCli(['verify-export', path, designation, '--json']);
      expect(json.status, contentType).toBe(1);
      const refusal = verdictOf(json);
      expect(refusal, contentType).toMatchObject({ ok: false, code: 'BAD_PROTECTED_HEADER' });
      expect(String(refusal.message), contentType).toContain(`typ=${contentType}`);
      expect(refusal.contentType, contentType).toBeUndefined();
    }
    const human = runCli(['verify-export', packPath, `--key=${RECEIPT_PUBLIC_B64URL}`]);
    expect(human.status).toBe(1);
    expect(human.stderr).toContain('verification failed (BAD_PROTECTED_HEADER): ');
    expect(human.stderr).toContain(`typ=${PACK_CONTENT_TYPE}`);
  });

  it('answers the type before it asks for a key, so an undesignated run still says what the file is not', () => {
    // Two different refusals, in the order that keeps a report honest: a document of another shape is a
    // fact about the document, and a run that named no key is a fact about the call.
    const wrongType = runCli(['verify-pack', exportPath, '--json']);
    expect(wrongType.status).toBe(1);
    expect(String(verdictOf(wrongType).message)).toContain(`typ=${EXPORT_CONTENT_TYPE}`);
    const rightType = runCli(['verify-pack', packPath]);
    expect(rightType.status).toBe(2);
    expect(rightType.stderr).toContain(`--key is required to verify ${PACK_CONTENT_TYPE}`);
  });

  it('names the verb it was run as when the arguments are not the ones that verb takes', () => {
    for (const verb of ['verify-pack', 'verify-export']) {
      const two = runCli([verb, 'a.cbor', 'b.cbor']);
      expect(two.status, verb).toBe(2);
      expect(two.stderr, verb).toContain(`expected exactly one argument: '${verb} <document>'`);
      expect(runCli([verb]).status, verb).toBe(2);
    }
  });

  it('takes an export item through its companion over the pin, and refuses the item without it', () => {
    const document = exportVector('companion-handed-and-checked');
    const path = written('pinned-export-companion.cbor', document.bytes);
    const missing = runCli(['verify-export', path, `--key=${EXPORT_KEY_B64URL}`, '--json']);
    expect(missing.status).toBe(1);
    // Accepted as the right shape, then refused by the reader for what it was handed: the second refusal
    // is the export's own code and carries the type, which only a run that got past the pin can report.
    expect(verdictOf(missing)).toMatchObject({ ok: false, contentType: EXPORT_CONTENT_TYPE, code: 'EXPORT_ORIGINAL_UNAVAILABLE' });
    const first = document.companions[0];
    const companionPath = writtenUnderItsOwnName(first?.name ?? 'companion', first?.bytes ?? new Uint8Array());
    const handed = runCli(['verify-export', path, `--key=${EXPORT_KEY_B64URL}`, `--companion=${companionPath}`, '--json']);
    expect(handed.status).toBe(0);
    expect(verdictOf(handed)).toMatchObject({ ok: true, contentType: EXPORT_CONTENT_TYPE });
  });

  it('reads a companion named by itself, which is how a handover directory is stood in', () => {
    // The bare name is the spelling the option is documented by, so a caller inside the directory that
    // holds the originals has to be able to type it.
    const document = exportVector('companion-handed-and-checked');
    const path = written('bare-companion.cbor', document.bytes);
    const first = document.companions[0];
    const companionPath = writtenUnderItsOwnName(first?.name ?? 'companion', first?.bytes ?? new Uint8Array());
    const handed = runCli(['verify-export', path, `--key=${EXPORT_KEY_B64URL}`, `--companion=${first?.name ?? 'companion'}`, '--json'], dirname(companionPath));
    expect(handed.stderr).toBe('');
    expect(handed.status).toBe(0);
    expect(verdictOf(handed)).toMatchObject({ ok: true, contentType: EXPORT_CONTENT_TYPE });
  });

  it('accepts a designation it will not consult and says so, which is what a run across a bundle needs', () => {
    // No option belongs to one verb alone: a caller looping a directory hands the same flags to every
    // file, and an unused designation is disclosed rather than dropped.
    const result = runCli(['verify-pack', packPath, `--key=${RECEIPT_PUBLIC_B64URL}`, manifestDesignation, '--json']);
    expect(result.status).toBe(0);
    // One entry per designated key, plus the line that says where the keys came from, which carries no
    // key of its own and so arrives as a null member of the array rather than as a missing one.
    const rows = verdictOf(result).keyDesignations as Array<Record<string, unknown> | null>;
    const manifestRow = rows.filter((one): one is Record<string, unknown> => one !== null && one.source === '--manifest-key');
    expect(manifestRow.map((one) => one.consulted)).toEqual([false]);
  });
});
