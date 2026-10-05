import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ReceiptError,
  SdkError,
  assessCapture,
  captureRecordKey,
  fromBase64Url,
  parseCaptureRecord,
  toBase64Url,
  toHex,
  verifyReceipt,
  type AssessCaptureParams,
  type AshaveriPolicy,
  type EvidenceTrustAnchors,
} from '@ashaveri/sdk';
import { describe, expect, it } from 'vitest';
import { DATA } from '../src/index.js';
import { readSourceFile, unionMembers } from './doc-contract.js';

/**
 * The published capture vectors, replayed the way a port replays them: take the record out of the file, hand the
 * reader the pins and the clock the file states beside it, and compare the answer with the answer the file states.
 * Nothing here computes an expected verdict out of a rule written again in this file; the statuses, the two halves
 * of each verdict, the refusal codes and the refusal sentences are data in `data/capture-v1.json`, and the only
 * question asked of the shipped code is whether it answers as the file says it does. Each published row is a test
 * of its own, so a row that stopped being replayed would have to be skipped rather than silently pass.
 *
 * Four more things are checked on the way, because a suite whose rows are documents is only as good as the claims
 * it can be read for. The first is that every refusal really refuses *at the step the row names*: a reader that
 * took a document a row states as refused would leave that row silent, and a reader that moved a refusal from the
 * layout to the reading would leave it reading as a fault it does not describe. So each refused row runs through
 * `parseCaptureRecord` and `assessCapture` apart, and the two answers are required to agree with `stage`. The
 * second is that no code the shipped capture reader raises is left unreached, read out of
 * `packages/sdk/src/capture.ts` rather than copied here, which is the only way a refusal added on that side and
 * never vectored by a row stops being invisible. The third is that the bytes this suite captures are the bytes the
 * repository already publishes: every published row is required to state `data/receipts/receipt-valid-v1.cbor` as
 * its original byte for byte except the four the document names, and `verifyReceipt` is asked of those bytes under
 * the key `data/keys/receipt-key-v1.json` publishes, so the suite stands on a document another suite already seals
 * rather than on a fixture that merely looks like one. The fourth holds the counts `docs/vectors.md` states about
 * these rows against the rows, because a number written down beside a table is a claim that outlives what it counted.
 */

const file = JSON.parse(readFileSync(join(DATA, 'capture-v1.json'), 'utf8')) as CaptureVectorFile;
const VECTORS_DOC = fileURLToPath(new URL('../../../docs/vectors.md', import.meta.url));
const CAPTURE_SOURCE = '../../sdk/src/capture.ts';
const SDK_ERRORS = '../../sdk/src/errors.ts';
const RECEIPT_ERRORS = '../../receipt/src/errors.ts';
/** The seven members capture version one defines, which is the closure every row of this suite is read under. */
const RECORD_MEMBERS = ['v', 'original', 'acquired', 'manifests', 'check', 'context', 'trust'];

interface CaptureVectorFile {
  readonly version: number;
  readonly description: string;
  readonly layout: {
    readonly codes: readonly string[];
    readonly keyMaterial: readonly { readonly id: string; readonly kidHex: string; readonly publicKeyBase64Url: string }[];
    readonly [key: string]: unknown;
  };
  readonly vectors: readonly AcceptedRow[];
  readonly refusals: readonly RefusalRow[];
}

/** The caller's side of one row: its own pins, its own roots, and the clock it hands. */
interface Read {
  policy?: { keys?: Record<string, string>; maxReceiptAgeSeconds?: number; maxEvidenceAgeSeconds?: number };
  anchors?: Record<string, string[]>;
  atMillis: number;
}

interface Row {
  readonly name: string;
  readonly note: string;
  readonly record: Record<string, unknown>;
  readonly read: Read;
}

interface AcceptedRow extends Row {
  readonly status: 'repeated' | 'qualified' | 'unassessed';
  readonly stated: Record<string, unknown>;
  readonly repeated: {
    readonly sha256: string;
    readonly signatureVerifiedWithOwnPins: boolean;
    readonly signingKid: string | null;
    readonly rootsMatched: readonly string[];
  };
  readonly absences: readonly Record<string, unknown>[];
  readonly qualifications: readonly string[];
  readonly recordKey: string;
}

interface RefusalRow extends Row {
  readonly stage: 'layout' | 'reading';
  readonly code: string;
  readonly message: string;
}

/** Every published row, tagged with the direction it states, which is what a per-row test dispatches on. */
type Replay =
  | { readonly kind: 'accepted'; readonly name: string; readonly row: AcceptedRow }
  | { readonly kind: 'refusal'; readonly name: string; readonly row: RefusalRow };

const replays: readonly Replay[] = [
  ...file.vectors.map((one): Replay => ({ kind: 'accepted', name: one.name, row: one })),
  ...file.refusals.map((one): Replay => ({ kind: 'refusal', name: one.name, row: one })),
];

const bytes = (base64url: string): Uint8Array => fromBase64Url(base64url);

const originalOf = (record: Record<string, unknown>): Record<string, unknown> =>
  record['original'] as Record<string, unknown>;

/** The caller's parameters, rebuilt out of the published row, which is what makes a replay a replay. */
function paramsOf(row: Row): AssessCaptureParams {
  const policy: AshaveriPolicy | undefined =
    row.read.policy === undefined
      ? undefined
      : {
          keys: row.read.policy.keys,
          ...(row.read.policy.maxReceiptAgeSeconds === undefined ? {} : { maxReceiptAgeSeconds: row.read.policy.maxReceiptAgeSeconds }),
          ...(row.read.policy.maxEvidenceAgeSeconds === undefined ? {} : { maxEvidenceAgeSeconds: row.read.policy.maxEvidenceAgeSeconds }),
        };
  const anchors: EvidenceTrustAnchors | undefined =
    row.read.anchors === undefined
      ? undefined
      : (Object.fromEntries(
          Object.entries(row.read.anchors).map(([family, roots]) => [family, roots.map((one) => bytes(one))]),
        ) as EvidenceTrustAnchors);
  return {
    record: row.record,
    ...(policy === undefined ? {} : { policy }),
    ...(anchors === undefined ? {} : { anchors }),
    nowMillis: row.read.atMillis,
  };
}

/** What a shipped step answered: its code and its sentence, or `ok` where it answered by handing something back. */
function answered(run: () => unknown): { readonly outcome: string; readonly message: string } {
  try {
    run();
    return { outcome: 'ok', message: '' };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { outcome: err.code, message: err.message };
    throw err;
  }
}

function acceptedNamed(name: string): AcceptedRow {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`data/capture-v1.json publishes no accepted row named ${name}`);
  return found;
}

function refusalNamed(name: string): RefusalRow {
  const found = file.refusals.find((one) => one.name === name);
  if (found === undefined) throw new Error(`data/capture-v1.json publishes no refusal named ${name}`);
  return found;
}

/**
 * The codes `packages/sdk/src/capture.ts` raises itself, read out of the three call forms that name one rather
 * than copied into this file. A code the reader raises and no row reaches is a refusal published nowhere, which is
 * the state a vector family has to be re-run into rather than re-remembered into.
 */
function codesTheReaderRaises(): string[] {
  const source = readSourceFile(CAPTURE_SOURCE);
  const patterns = [
    /refused\(\s*'([A-Z][A-Z0-9_]+)'/gu,
    /new SdkError\(\s*'([A-Z][A-Z0-9_]+)'/gu,
    /new ReceiptError\(\s*'([A-Z][A-Z0-9_]+)'/gu,
  ];
  const found = patterns.flatMap((pattern) => [...source.matchAll(pattern)].map((each) => each[1]!));
  return [...new Set(found)].sort();
}

/** The facts a held collateral slot owes, read out of the list the shipped reader asks them from. */
function observationMembers(): string[] {
  const literal = /const OBSERVATION_MEMBERS = \[([\s\S]*?)\] as const;/u.exec(readSourceFile(CAPTURE_SOURCE));
  if (literal === null) throw new Error('the capture reader no longer states the members of a collateral slot as a list');
  return [...literal[1]!.matchAll(/'([a-zA-Z]+)'/gu)].map((each) => each[1]!);
}

const kebab = (member: string): string => member.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`);

/** The Capture bullet of `docs/vectors.md`, read as one run of prose because its sentences wrap across lines. */
function captureBullet(): string {
  const doc = readFileSync(VECTORS_DOC, 'utf8');
  const start = doc.indexOf('\n- **Capture record.');
  if (start < 0) throw new Error('docs/vectors.md states no Capture record bullet to read');
  let end = doc.length;
  for (const marker of ['\n- **', '\n## ']) {
    const found = doc.indexOf(marker, start + 5);
    if (found > 0 && found < end) end = found;
  }
  return doc.slice(start, end).replace(/\n\s*/gu, ' ');
}

/** One count that bullet states about these rows, taken back out of the sentence that states it. */
function countInBullet(states: RegExp, what: string): number {
  const stated = states.exec(captureBullet());
  if (stated === null) throw new Error(`the Capture bullet of docs/vectors.md states no count of ${what}`);
  return Number(stated[1]);
}

describe('data/capture-v1.json', () => {
  it('states a rule in prose and names the two readers it is read by', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(80);
    expect(String(file.layout.record)).toContain('packages/sdk/schemas/capture-v1.schema.json');
    expect(file.layout.prose).toBe('docs/capture-v1.md');
    expect(String(file.layout.reader)).toContain('parseCaptureRecord');
    expect(String(file.layout.reader)).toContain('assessCapture');
    expect(file.vectors.length, 'a suite with too few accepted rows cannot state the states a record arrives in').toBeGreaterThanOrEqual(8);
    expect(file.refusals.length, 'a suite of accepted rows would prove nothing about a reader\'s refusals').toBeGreaterThanOrEqual(16);
    for (const code of file.layout.codes) {
      expect(file.refusals.some((one) => one.code === code), `${code} is listed and refused by no row`).toBe(true);
    }
  });

  it.each(replays)('$name replays as the file says', (one) => {
    const parsed = answered(() => parseCaptureRecord(one.row.record));
    const assessed = answered(() => assessCapture(paramsOf(one.row)));
    if (one.kind === 'accepted') {
      const row = one.row;
      expect(parsed.outcome, `${row.name}: the layout refused a row this file publishes as taken`).toBe('ok');
      expect(assessed.outcome, `${row.name}: the reading refused a row this file publishes as taken`).toBe('ok');
      const verdict = assessCapture(paramsOf(row));
      expect(verdict.status, `${row.name}: the reader answers ${verdict.status}`).toBe(row.status);
      // The verdict's two halves are published apart, so both are compared as the objects the reader returned
      // rather than as a status word that could hide one half being read as the other.
      expect(verdict.stated, `${row.name}: the reader states something other than what the record claims`).toEqual(row.stated);
      expect(verdict.repeated.sha256, `${row.name}: a different digest computed over the same bytes`).toBe(row.repeated.sha256);
      expect(verdict.repeated.signatureVerifiedWithOwnPins).toBe(row.repeated.signatureVerifiedWithOwnPins);
      expect(verdict.repeated.signingKid, `${row.name}: a different kid resolved from the same header`).toBe(row.repeated.signingKid);
      expect(verdict.repeated.rootsMatched, `${row.name}: a different set of pinned roots matched`).toEqual(row.repeated.rootsMatched);
      expect(verdict.absences, `${row.name}: a different set of declared absences`).toEqual(row.absences);
      expect(verdict.qualifications, `${row.name}: a different set of qualifications`).toEqual(row.qualifications);
      expect(captureRecordKey(parseCaptureRecord(row.record)), `${row.name}: a different key for the same record`).toBe(row.recordKey);
      return;
    }
    const row = one.row;
    expect(assessed.outcome, `${row.name}: the reader took a document this row states as refused`).not.toBe('ok');
    const given = parsed.outcome === 'ok' ? assessed : parsed;
    expect(given.outcome, `${row.name}: the reader answers ${given.outcome}, not the ${row.code} the file states`).toBe(row.code);
    expect(given.message, `${row.name}: this reader gave the refusal in other words than the file states`).toBe(row.message);
  });

  it('refuses every published refusal at the step the row names', () => {
    for (const row of file.refusals) {
      const parsed = answered(() => parseCaptureRecord(row.record));
      const assessed = answered(() => assessCapture(paramsOf(row)));
      if (row.stage === 'layout') {
        expect(parsed.outcome, `${row.name}: the layout took a document this row states it refuses`).not.toBe('ok');
        expect(parsed.outcome, `${row.name}: the layout answered another code than the row states`).toBe(row.code);
        // `assessCapture` parses, so a layout refusal reaches it as the same refusal and no further.
        expect(assessed.outcome, `${row.name}: the reading answered before the layout had`).toBe(row.code);
        expect(assessed.message, `${row.name}: the two published steps gave two sentences for one fault`).toBe(row.message);
        continue;
      }
      expect(parsed.outcome, `${row.name}: the layout refused the document this row states the reading refuses`).toBe('ok');
      expect(assessed.outcome, `${row.name}: the reading took a document this row states it refuses`).toBe(row.code);
      expect(assessed.message, `${row.name}: the reading gave another sentence than the row states`).toBe(row.message);
    }
  });

  it('reaches every code the capture reader raises and names no code no registry declares', () => {
    const raised = codesTheReaderRaises();
    expect(raised.length, 'the capture source names no code, so this check guards nothing').toBeGreaterThanOrEqual(4);
    const reached = new Set(file.refusals.map((one) => one.code));
    for (const code of raised) {
      expect(reached.has(code), `${code} is raised by the shipped reader and no published row reaches it`).toBe(true);
    }
    // Every word this suite refuses with is one a registry declares, so a port learns nothing out here that it did
    // not have to learn anyway.
    const declared = new Set([
      ...unionMembers('SdkErrorCode', SDK_ERRORS),
      ...unionMembers('ReceiptErrorCode', RECEIPT_ERRORS),
    ]);
    const undeclared = [...reached].filter((code) => !declared.has(code));
    expect(undeclared, 'a published refusal names a code no registry declares').toEqual([]);
    expect([...reached].sort(), 'the codes the rows refuse with and the list the file publishes').toEqual(
      [...file.layout.codes].sort(),
    );
  });

  it('states one refusal per fact a held collateral slot owes', () => {
    // The list the reader asks them from, not a list this file remembers.
    const members = observationMembers();
    expect(members.length).toBe(8);
    for (const member of members) {
      const row = file.refusals.find((one) => one.name === `held-collateral-stating-no-${kebab(member)}`);
      expect(row, `no published row states \`${member}\` missing from a held collateral slot`).toBeDefined();
      expect(row?.message, `${String(row?.name)}: the refusal does not name the member it found missing`).toContain(
        `context.collateral.${member}`,
      );
      expect(row?.code, `${String(row?.name)}: a missing collateral fact answered with another code`).toBe('NOT_CAPTURE_RECORD');
    }
    expect(
      file.refusals.filter((one) => one.name.startsWith('held-collateral-stating-no-')).length,
      'the rows stating a collateral member missing are not one per member',
    ).toBe(members.length);
    // And a null is a statement rather than a hole: the identity one row states as null is taken.
    expect(acceptedNamed('identity-stating-none').status).toBe('repeated');
  });

  it('captures the receipt the repository already publishes, under the key it already publishes', () => {
    const key = JSON.parse(readFileSync(join(DATA, 'keys', 'receipt-key-v1.json'), 'utf8')) as {
      privateKey: string;
      publicKey: string;
      kid: string;
    };
    const publicKey = new Uint8Array(Buffer.from(key.publicKey, 'hex'));
    const committed = new Uint8Array(readFileSync(join(DATA, 'receipts', 'receipt-valid-v1.cbor')));
    const honest = acceptedNamed('exact-original-bytes-repeated');
    const original = bytes(String(originalOf(honest.record)['bytes']));
    expect(toHex(original), 'the captured bytes are not the document the receipt suite publishes').toBe(toHex(committed));
    // Those bytes are signed by the key the fixtures package publishes, and by the reader that checks them.
    expect(() => verifyReceipt(original, { publicKey, nowSeconds: Math.floor(honest.read.atMillis / 1_000) })).not.toThrow();
    expect(honest.repeated.signingKid).toBe(key.kid);
    expect(honest.stated['sha256']).toBe(toHex(sha256(committed)));
    const publishedKey = file.layout.keyMaterial.find((one) => one.id === 'receipt-fixture-key');
    expect(publishedKey?.kidHex, 'the suite publishes no receipt fixture key').toBe(key.kid);
    expect(publishedKey?.publicKeyBase64Url, 'the published public half is not the committed one').toBe(toBase64Url(publicKey));
    expect(
      honest.read.policy?.keys?.[key.kid],
      'the honest row pins no key under the kid its own header names',
    ).toBe(toBase64Url(publicKey));
    // And the claim is not the honest row's alone: every published row states that document as its original unless
    // it names the bytes it states instead, which is what the four below do and what the document counts. The count
    // is taken back out of the sentence rather than kept here, so a row that quietly began to state other bytes
    // moves the document or fails this run, and a suite that gained an unremarked original fails it too.
    const statedBytes = (record: Record<string, unknown>): string => String(originalOf(record)['bytes']);
    const apart = replays.filter((one) => statedBytes(one.row.record) !== toBase64Url(committed));
    expect(
      apart.map((one) => one.name).sort(),
      'the rows stating an original other than the committed receipt are not the ones the prose names',
    ).toEqual([
      'manifest-original-claiming-no-signature',
      'one-bit-changed-inside-the-original',
      'reserialized-envelope-against-the-stated-digest',
      'reserialized-envelope-stated-as-its-own-original',
    ]);
    expect(
      countInBullet(/every row but ([0-9]+) are the document/u, 'the rows stating another original'),
      'the document counts a different number of rows stating another original than the rows do',
    ).toBe(apart.length);
  });

  it('hands back the stored bytes unchanged on every accepted row', () => {
    for (const row of file.vectors) {
      const verdict = assessCapture(paramsOf(row));
      expect(
        toHex(verdict.repeated.originalBytes),
        `${row.name}: the reader handed back bytes other than the ones the record holds`,
      ).toBe(toHex(bytes(String(originalOf(row.record)['bytes']))));
      // The two halves of one claim: the record's stated digest and this reader's recomputation over the bytes.
      expect(verdict.stated.sha256, `${row.name}: the verdict's halves disagree about one digest`).toBe(verdict.repeated.sha256);
      expect(verdict.repeated.sha256, `${row.name}: the digest recomputed is not the one the record states`).toBe(
        String(originalOf(row.record)['sha256']),
      );
    }
  });

  it('keys a purported equivalent apart from the document it copies, and refuses it twice over', () => {
    const against = refusalNamed('reserialized-envelope-against-the-stated-digest');
    const asItsOwn = refusalNamed('reserialized-envelope-stated-as-its-own-original');
    // One re-framed envelope, stated two ways: the same bytes in both rows and a different digest claimed for them.
    expect(String(originalOf(against.record)['bytes'])).toBe(String(originalOf(asItsOwn.record)['bytes']));
    expect(String(originalOf(against.record)['sha256'])).not.toBe(String(originalOf(asItsOwn.record)['sha256']));
    expect(against.stage).toBe('layout');
    expect(against.code).toBe('EVIDENCE_DIGEST_MISMATCH');
    expect(asItsOwn.stage).toBe('reading');
    expect(asItsOwn.code).toBe('MALFORMED_CBOR');
    // A record of the re-framed bytes is a record of a different document, and the two key apart under the reader's
    // own identity function, which is the claim the second row's note makes.
    const honest = acceptedNamed('exact-original-bytes-repeated');
    expect(honest.recordKey).toBe(captureRecordKey(parseCaptureRecord(honest.record)));
    expect(
      captureRecordKey(parseCaptureRecord(asItsOwn.record)),
      'the re-framed record keys as the record of the bytes the source produced',
    ).not.toBe(honest.recordKey);
  });

  it('keeps the two absences apart, and both apart from a hole', () => {
    const neverProduced = acceptedNamed('collateral-absent-at-source-qualified');
    const didNotLook = acceptedNamed('collateral-not-taken-in-unassessed');
    expect(neverProduced.absences).toEqual([
      { slot: 'context.collateral', presence: 'absent-at-source', reason: 'the source served no collateral answer' },
    ]);
    expect(didNotLook.absences).toEqual([
      { slot: 'context.collateral', presence: 'not-taken-in', reason: 'the route was never asked' },
    ]);
    expect(neverProduced.status).toBe('qualified');
    expect(didNotLook.status).toBe('unassessed');
    // The third spelling of the same hole is refused rather than read, which is what the two above are here for.
    expect(refusalNamed('collateral-slot-left-out-of-the-context').code).toBe('NOT_CAPTURE_RECORD');
    expect(refusalNamed('validity-slot-left-out-of-the-context').message).toContain('validity');
    // Each of the three slots a record can leave stated as absent is named by an accepted row, so no reader
    // merges them into one "nothing here" verdict.
    const slots = new Set(file.vectors.flatMap((one) => one.absences.map((absence) => String(absence['slot']))));
    expect([...slots].sort()).toEqual(['context.collateral', 'context.validity', 'manifests.deployment']);
  });

  it('never reads a missing pin as a pass, and reaches `repeated` only from a caller\'s own pins', () => {
    const unpinned = acceptedNamed('caller-holding-no-pin-at-all');
    expect(unpinned.status).toBe('unassessed');
    expect(unpinned.repeated.signatureVerifiedWithOwnPins).toBe(false);
    expect(unpinned.repeated.rootsMatched).toEqual([]);
    expect(unpinned.qualifications.length).toBeGreaterThanOrEqual(2);
    const repeated = file.vectors.filter((one) => one.status === 'repeated');
    expect(repeated.length).toBeGreaterThanOrEqual(5);
    for (const one of repeated) {
      expect(one.repeated.signatureVerifiedWithOwnPins, `${one.name} reaches \`repeated\` without a leg that ran`).toBe(true);
      expect(one.absences, `${one.name} reaches \`repeated\` while the record states an absence`).toEqual([]);
      expect(one.qualifications, `${one.name} reaches \`repeated\` with a qualification beside it`).toEqual([]);
    }
    // A vendor chain this reader does not walk is named as a leg it did not run, never as a soft pass.
    const vendor = acceptedNamed('vendor-signed-original-this-reader-does-not-walk');
    expect(vendor.status).toBe('unassessed');
    expect(vendor.qualifications.join(' ')).toContain('verifyCompletionEvidence');
  });

  it('straddles the one width the layout bounds a stated address at', () => {
    const within = acceptedNamed('address-at-the-last-byte-a-reference-carries');
    const past = refusalNamed('address-one-byte-past-what-a-reference-carries');
    const width = (record: Record<string, unknown>): number =>
      new TextEncoder().encode(
        String(((record['context'] as Record<string, unknown>)['collateral'] as Record<string, unknown>)['request']),
      ).length;
    expect(width(within.record)).toBe(2_048);
    expect(width(past.record)).toBe(2_049);
    expect(within.status).toBe('repeated');
    expect(past.code).toBe('NOT_CAPTURE_RECORD');
    expect(past.message).toContain('2048');
  });

  it('names in its document the counts its rows carry', () => {
    expect(
      countInBullet(/publishes ([0-9]+) accepted rows/u, 'the accepted rows'),
      'the document counts a different number of accepted rows than the file publishes',
    ).toBe(file.vectors.length);
    expect(
      countInBullet(/and ([0-9]+) refusals/u, 'the refusals'),
      'the document counts a different number of refusals than the file publishes',
    ).toBe(file.refusals.length);
    expect(
      countInBullet(/([0-9]+) of the refusals state one fact a held collateral slot leaves out/u, 'the collateral member refusals'),
      'the document speaks of the collateral member refusals at a count the rows do not carry',
    ).toBe(observationMembers().length);
  });

  it('states one whole capture record per row, read under the clock the row hands', () => {
    for (const one of replays) {
      for (const member of Object.keys(one.row.record)) {
        expect(RECORD_MEMBERS, `${one.name} carries a member capture version one does not define: ${member}`).toContain(member);
      }
      // One row states a capture version this format has no reader for, and it is the row that names it.
      expect(one.row.record['v'], `${one.name}: a row that names no capture version`).toBe(one.name === 'capture-version-two' ? 2 : 1);
      expect(one.row.read.atMillis, `${one.name}: a row read on no clock of its own`).toBeGreaterThan(0);
      expect(one.row.note.length, `${one.name}: a row with no sentence about what it turns on`).toBeGreaterThan(60);
    }
  });
});
