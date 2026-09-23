import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519';
import {
  EXPORT_CONTENT_TYPE,
  decodeCanonical,
  decodeExport,
  encodeCanonical,
  exportSigStructure,
  fromBase64Url,
  sealExport,
  signingKeyFromSeed,
  toHex,
  verifyExport,
  type ExportChainedItem,
  type ExportItem,
} from '@ashaveri/receipt';
import { loadExportVectors, type ExportVector, type ExportVectorFile } from '../src/index.js';
import { unionMembers } from './doc-contract.js';

/**
 * The published export vectors, replayed the way a port replays them: read the document out of the file,
 * hand the reader the arguments the file states beside it, and compare the answer with the verdict the file
 * states. Nothing here computes an expected value from the reader: the verdicts, the item names, the arms
 * and the walk orders are data in `data/export-v1.json`, and the only question asked of the code is whether
 * it answers as the file says it does.
 *
 * Two things are checked on the way, because a suite of documents is only as good as the documents. Each
 * file is re-encoded from its own decoded form, so a byte that only this implementation's writer produces
 * would show up as a port's disagreement rather than as a silent convention. And every code of the export
 * family in the registry is required to be reached by a committed document, which is the only way a refusal
 * added to `errors.ts` without a case cannot pass unnoticed.
 */

const file = loadExportVectors();
const ERRORS = '../../../packages/receipt/src/errors.ts';
const PACK_TWIN = '../../../packages/receipt/schemas/pack-v1.schema.json';
const SUITE_KEY = signingKeyFromSeed(new Uint8Array(32).fill(23));

/** The four elements of a sealed document, for the cases that rebuild one around a different payload. */
function envelopeOf(bytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a published document is not a four-element envelope');
  return contents;
}

/** One item as the format writes it, so a rebuilt document differs from its source in no position. */
function itemMap(one: ExportItem | ExportChainedItem): Map<string, unknown> {
  // The order is not the format's to keep: canonical CBOR sorts map keys bytewise, so a rebuilt item whose
  // members were inserted in another order still yields the same bytes.
  const map = new Map<string, unknown>([
    ['id', one.id],
    ['iat', one.iat],
    ['d', one.d],
    [
      'orig',
      one.orig.k === 'inline'
        ? new Map<string, unknown>([['k', 'inline'], ['bytes', one.orig.bytes]])
        : new Map<string, unknown>([['k', 'companion'], ['name', one.orig.name]]),
    ],
  ]);
  if ('p' in one) map.set('p', one.p);
  return map;
}

function vectorNamed(name: string): ExportVector {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`export-v1.json publishes no ${name} case`);
  return found;
}

/** The key a case is read with: the suite key unless the file says the reader brought another. */
function keyFor(one: ExportVector): Uint8Array {
  if (one.read.keySeed === undefined) return SUITE_KEY.publicKey;
  return signingKeyFromSeed(new Uint8Array(32).fill(one.read.keySeed)).publicKey;
}

/** What the published document gets from the reader, with the published arguments beside it. */
function attempt(one: ExportVector): { verdict: string; message: string } {
  try {
    const verified = verifyExport(fromBase64Url(one.documentBase64Url), keyFor(one), {
      companions: one.read.companions === undefined ? undefined : new Map(one.read.companions.map((each) => [each.name, fromBase64Url(each.bytesBase64Url)])),
      expectedAnchor: one.read.expectedAnchorHex === undefined ? undefined : fromHex(one.read.expectedAnchorHex),
      expectedHead: one.read.expectedHeadHex === undefined ? undefined : fromHex(one.read.expectedHeadHex),
    });
    const reported = verified.outcome.kind;
    if (one.outcome !== undefined && reported !== one.outcome) {
      return { verdict: `${reported}-arm`, message: `the reader reported the ${reported} arm` };
    }
    if (one.walk !== undefined) {
      const order = reported === 'anchored' && verified.outcome.kind === 'anchored' ? verified.outcome.walked.map((each) => each.id).join(' ') : '';
      if (order !== one.walk.join(' ')) return { verdict: `walk:${order}`, message: `the walk reached ${order}` };
    }
    return { verdict: 'verify-ok', message: '' };
  } catch (err) {
    if (err instanceof Error && 'code' in err && typeof err.code === 'string') return { verdict: err.code, message: err.message };
    return { verdict: `UNCODED:${String(err)}`, message: String(err) };
  }
}

/** The verdict the published document gets, which is the fact a port compares its own against. */
function answer(one: ExportVector): string {
  return attempt(one).verdict;
}

/** The sentence that came with the verdict, which is where an item or a name is told. */
function failureMessage(one: ExportVector): string {
  return attempt(one).message;
}

function fromHex(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

/** Every code of the export family the registry declares, read out of the declaration itself. */
function registryCodes(): string[] {
  return unionMembers('ReceiptErrorCode', ERRORS).filter((code) => code.startsWith('EXPORT_'));
}

function itemsOf(one: ExportVector): Array<ExportItem | ExportChainedItem> {
  const decoded = decodeExport(fromBase64Url(one.documentBase64Url));
  const collection = decoded.manifest.collection;
  return collection.k === 'void' ? [] : [...collection.items];
}

/** The members the pack twin requires of a manifest, read out of that file rather than repeated here. */
function packManifestRequired(): string[] {
  const twin = JSON.parse(readFileSync(fileURLToPath(new URL(PACK_TWIN, import.meta.url)), 'utf8')) as {
    $defs?: { manifest?: { required?: unknown } };
  };
  const required = twin.$defs?.manifest?.required;
  if (!Array.isArray(required) || required.some((one) => typeof one !== 'string')) {
    throw new Error('the pack twin declares no list of required manifest members to compare with');
  }
  return required as string[];
}

describe('the export vectors', () => {
  it('are a suite the inventory and the format both point at', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(0);
    expect(file.layout.contentType).toBe(EXPORT_CONTENT_TYPE);
    expect(file.layout.headerLabels).toEqual({ alg: 1, typ: 3, kid: 4 });
    expect(file.layout.manifestFields).toEqual(['v', 'at', 'assessment', 'collection', 'claim']);
    expect(file.layout.collectionArms).toEqual(['anchored', 'plain', 'void']);
    expect(file.layout.originalArms).toEqual(['inline', 'companion']);
    expect(file.layout.framing).toBe('docs/receipt-spec.md section 5.2');
    for (const path of [file.layout.format, file.layout.twin, file.layout.document]) {
      expect(existsSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url))), `${path} is named by the suite and is not there`).toBe(true);
    }
    // The names of the three artifacts are one fact shared between the vectors, the format and the
    // document, so a file that moved has to move here too.
    expect(readFileSync(fileURLToPath(new URL(`../../../${file.layout.format}`, import.meta.url)), 'utf8')).toContain('"ashaveri/export"');
  });

  it('answer as each case promises, on the arguments the case is handed', () => {
    const outcomes = file.vectors.map((one) => `${one.name}: ${answer(one)}`);
    const promised = file.vectors.map((one) => `${one.name}: ${one.verdict}`);
    expect(outcomes).toEqual(promised);
    for (const one of file.vectors) {
      if (one.item === undefined) continue;
      expect(answer(one), `${one.name} did not answer the verdict it states}`).toBe(one.verdict);
      expect(failureMessage(one), `${one.name} refused without naming ${one.item}`).toContain(one.item);
    }
  });

  it('reaches every code of the export family from a committed document', () => {
    const reached = new Set(file.vectors.map((one) => one.verdict));
    const declared = registryCodes();
    expect(declared.length, 'the registry declares no export codes to reach').toBeGreaterThan(0);
    for (const code of declared) {
      expect([...reached], `${code} is declared and no published document reaches it`).toContain(code);
    }
    // And the file's own roster of answers is exactly what its cases state, so a code that left the suite
    // would be caught from both sides.
    expect([...file.layout.codes].sort()).toEqual([...reached].sort());
  });

  it('covers the refusals a handover is judged on, and the shapes it is not', () => {
    const verdicts = new Map(file.vectors.map((one) => [one.name, one.verdict]));
    // The three shapes that pass, including the one that carries nothing.
    expect(verdicts.get('well-formed-void')).toBe('verify-ok');
    expect(verdicts.get('well-formed-plain')).toBe('verify-ok');
    expect(verdicts.get('well-formed-anchored')).toBe('verify-ok');
    for (const [name, verdict] of [
      ['empty-collection-unstated', 'EXPORT_BAD_MANIFEST'],
      ['original-bytes-edited', 'EXPORT_DIGEST_MISMATCH'],
      ['companion-not-handed', 'EXPORT_ORIGINAL_UNAVAILABLE'],
      ['payload-byte-changed', 'INVALID_SIGNATURE'],
      ['walk-short-of-head', 'EXPORT_CHAIN_BROKEN'],
      ['walk-forked-at-the-anchor', 'EXPORT_CHAIN_BROKEN'],
      ['item-parked-beside-the-run', 'EXPORT_ITEM_UNREACHED'],
      ['duplicate-item-id', 'EXPORT_DUPLICATE_ID'],
      ['unknown-manifest-member', 'EXPORT_BAD_MANIFEST'],
      ['unknown-item-member', 'EXPORT_BAD_MANIFEST'],
      ['unknown-assessment-member', 'EXPORT_BAD_MANIFEST'],
      ['wrong-content-type', 'EXPORT_BAD_HEADER'],
      ['pack-read-as-export', 'EXPORT_BAD_HEADER'],
      ['manifest-version-unknown', 'EXPORT_UNSUPPORTED_VERSION'],
      ['claim-after-assembly', 'EXPORT_BAD_MANIFEST'],
      ['companion-name-is-a-path', 'EXPORT_BAD_MANIFEST'],
      ['wrong-key-offered', 'EXPORT_KID_MISMATCH'],
      ['untagged-envelope', 'NOT_COSE_SIGN1'],
      ['truncated-document', 'EXPORT_MALFORMED_CBOR'],
    ] as const) {
      expect(verdicts.get(name), `${name} is not in the published suite`).toBe(verdict);
    }
    // The pair that states the bound of a walk rather than a refusal: the shorter run closes against the
    // head the writer signed for it, and the same document fails only for a reader that brought its own.
    expect(verdicts.get('hole-closed-without-a-pin')).toBe('verify-ok');
    expect(verdicts.get('rechained-to-a-shorter-head')).toBe('EXPORT_ENDPOINT_MISMATCH');
    expect(vectorNamed('hole-closed-without-a-pin').walk).toEqual(['r-0', 'r-2']);
  });

  it('publish documents that are canonical, whole and self-consistent', () => {
    for (const one of file.vectors) {
      const bytes = fromBase64Url(one.documentBase64Url);
      expect(bytes.length, `${one.name} states a length its bytes disagree with`).toBe(one.documentByteLength);
      if (one.verdict === 'EXPORT_MALFORMED_CBOR') {
        expect(() => decodeCanonical(bytes), `${one.name} decodes, which is what it is published to avoid`).toThrow();
        continue;
      }
      // A port that rebuilds the document from its own decoded form has to get the same bytes back, which
      // is the determinism promise the format makes and the only way a vector can teach it.
      expect(toHex(encodeCanonical(decodeCanonical(bytes))), `${one.name} is not written in the encoding it demands`).toBe(toHex(bytes));
    }
    for (const one of file.vectors.filter((each) => each.verdict === 'verify-ok')) {
      for (const item of itemsOf(one)) {
        if (item.orig.k !== 'inline') continue;
        expect(toHex(sha256(item.orig.bytes)), `${one.name} carries an item whose digest is not of its bytes`).toBe(toHex(item.d));
      }
    }
  });

  it('reads an anchored run in the order of the links, not the order of the array', () => {
    const one = vectorNamed('well-formed-anchored');
    const decoded = decodeExport(fromBase64Url(one.documentBase64Url));
    const collection = decoded.manifest.collection;
    if (collection.k !== 'anchored') throw new Error('the anchored case is not an anchored collection');
    expect(collection.anchor.length).toBe(32);
    expect(collection.head.length).toBe(32);
    expect(toHex(collection.anchor)).toBe('00'.repeat(32));
    // The published array order is the order the writer assembled it in, which is a fact about this file and
    // not a rule of the format. The reader is asked the same question with the array reversed and re-sealed,
    // and only a walk over the links survives that.
    const [header, , payload] = envelopeOf(fromBase64Url(one.documentBase64Url));
    const root = decodeCanonical(payload as Uint8Array);
    if (!(root instanceof Map)) throw new Error('the anchored case carries no manifest map');
    const rebuilt = new Map(root);
    rebuilt.set('collection', new Map<string, unknown>([
      ['k', 'anchored'],
      ['anchor', collection.anchor],
      ['head', collection.head],
      ['items', [...collection.items].reverse().map(itemMap)],
    ]));
    const bytes = encodeCanonical(rebuilt);
    const sealed = sealExport(header as Uint8Array, bytes, ed25519.sign(exportSigStructure(header as Uint8Array, bytes), SUITE_KEY.privateKey));
    const reread = verifyExport(sealed, SUITE_KEY.publicKey);
    if (reread.outcome.kind !== 'anchored') throw new Error('the reversed document was not read as an anchored run');
    expect(reread.outcome.walked.map((each) => each.id)).toEqual(one.walk);
  });

  it('keep the two containers apart in both directions', () => {
    const cases = new Map(file.crossReading.cases.map((one) => [one.name, one]));
    const asPack = cases.get('export-as-pack');
    expect(asPack, 'the suite publishes no export-as-pack case').toBeDefined();
    const payload = asPack?.manifest?.payload;
    if (payload === undefined || payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('the published export projection carries no manifest object');
    }
    // The pack twin's own required list, read out of its file: six members, of which an export names none
    // but the version and the assembly instant. A reader of the pack closes at that list, so this document
    // is refused by the shape before any of its contents is weighed. The two schema validations a port has
    // to run are in `packages/receipt/test/export.test.ts`, which is where a JSON Schema validator lives.
    const packRequired = packManifestRequired();
    const members = Object.keys(payload).sort();
    expect(members, 'the published projection is not the export manifest the vectors carry').toEqual([...file.layout.manifestFields].sort());
    for (const member of packRequired.filter((each) => !['v', 'at'].includes(each))) {
      expect(members, `an export manifest carries ${member}, which is what a pack reader would be looking for`).not.toContain(member);
    }
    expect(members, 'an export manifest carries the assessment a pack has no position for').toContain('assessment');
    expect(members, 'an export manifest carries the claim a pack has no position for').toContain('claim');
    // The other direction, which is a verdict this suite can state and a reader can reproduce.
    const asExport = cases.get('pack-as-export');
    expect(asExport?.documentBase64Url, 'the suite publishes no pack-as-export document').toBeDefined();
    let code = 'accepted';
    try {
      verifyExport(fromBase64Url(asExport?.documentBase64Url ?? ''), SUITE_KEY.publicKey);
    } catch (err) {
      code = err instanceof Error && 'code' in err ? String(err.code) : `UNCODED:${String(err)}`;
    }
    expect(code).toBe(asExport?.expected);
    expect(code).toBe('EXPORT_BAD_HEADER');
  });

  it('publishes a suite whose verdicts are the file and not the reader', () => {
    // `verdict` is the contract a port reads, so the field a reader is asked about has to be the one in the
    // file, unchanged: an answer recomputed at assertion time could not disagree with anything.
    const raw = JSON.parse(readFileSync(fileURLToPath(new URL('../data/export-v1.json', import.meta.url)), 'utf8')) as ExportVectorFile;
    expect(raw.vectors.map((one) => `${one.name}=${one.verdict}`)).toEqual(file.vectors.map((one) => `${one.name}=${one.verdict}`));
    expect(file.vectors.every((one) => one.verdict === 'verify-ok' || one.verdict.startsWith('EXPORT_') || one.verdict === 'INVALID_SIGNATURE' || one.verdict === 'NOT_COSE_SIGN1')).toBe(true);
    expect(new Set(file.vectors.map((one) => one.name)).size).toBe(file.vectors.length);
  });
});
