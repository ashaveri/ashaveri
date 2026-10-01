import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  INTEL_QE_IDENTITY,
  INTEL_TCB_INFO,
  appraiseCollateral,
  readServedCollateral,
  type CollateralOutcome,
  type CollateralQuery,
  type CollateralRefusal,
  type CollateralTransport,
  type OriginDeclaration,
  type ReadCollateral,
  type ReadOutcome,
} from '../src/index.js';
import {
  qeIdentity,
  secondsOf,
  servedAnswer,
  servedChain,
  servedChainOf,
  servedMemberText,
  servedSignatureMember,
  servedWrapperBody,
  tcbInfo,
  tcbInfoBody,
  testVendor,
} from './support/collateral-documents.js';

const FMSPC = '00906EA00000';
const CPU_TYPE = FMSPC.toLowerCase();
const LEVEL_DATE = '2026-09-01T00:00:00Z';
const NEXT_UPDATE = '2026-10-01T00:00:00Z';
const WITHIN = secondsOf('2026-09-15T00:00:00.000Z');
const AFTER = secondsOf('2026-11-15T00:00:00.000Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00.000Z');
const TCB_HEADER = INTEL_TCB_INFO.chainHeader as string;

/** The wrapper member each document is served under, read off the declaration that names it. */
const TCB_MEMBER = INTEL_TCB_INFO.window.documentMember as string;
const QE_MEMBER = INTEL_QE_IDENTITY.window.documentMember as string;

const vendor = testVendor();

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'intel-tcb-info',
    platform: 'tdx',
    cpuType: CPU_TYPE,
    level: { by: 'tcb-date', value: LEVEL_DATE },
    appraisalAt: WITHIN,
    roots: [vendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

/** The TCB Info document every case here is built from, in the member order the vendor writes it. */
function servedDocument(status = 'UpToDate'): Record<string, unknown> {
  return tcbInfo({
    fmspc: FMSPC,
    issueDate: LEVEL_DATE,
    nextUpdate: NEXT_UPDATE,
    levels: [{ tcbDate: LEVEL_DATE, tcbStatus: status }],
  });
}

function weigh(
  body: Uint8Array,
  chain: Uint8Array | null,
  declaration: OriginDeclaration = INTEL_TCB_INFO,
  over: Partial<CollateralQuery> = {},
): ReadOutcome {
  const asked = query(over);
  return readServedCollateral(body, chain, {
    query: asked,
    declaration,
    appraisalAt: asked.appraisalAt as number,
  });
}

function readOf(result: ReadOutcome): ReadCollateral {
  if ('read' in result) {
    return result.read;
  }
  throw new Error(`the answer was refused: ${result.refusal.code} ${result.refusal.detail}`);
}

function refusalOf(result: ReadOutcome): CollateralRefusal {
  if ('refusal' in result) {
    return result.refusal;
  }
  throw new Error(`the answer was weighed as ${result.read.vendorStatus}, but a refusal was expected`);
}

/** The origin answering the one caller that asks it, with the halves this case hands it. */
function answering(body: Uint8Array, chain: Uint8Array | null): CollateralTransport {
  return async () => new Response(body, chain === null ? {} : { headers: { [TCB_HEADER]: new TextDecoder().decode(chain) } });
}

async function ask(transport: CollateralTransport, over: Partial<CollateralQuery> = {}): Promise<CollateralOutcome> {
  return appraiseCollateral(query(over), { transport, clock: () => OBSERVED });
}

describe('the envelope the origin actually serves', () => {
  /**
   * What the signature covers is the document member's own span inside the body text, so this case proves the
   * reader weighed the bytes that arrived and not a copy re-made from them: the certificates are the ones the
   * header carried, in the order the header carried them, and the anchor named is the root the caller holds
   * rather than a name the reader recognised on the way.
   */
  it('weighs a served document under the root the caller names, over the span the body holds', () => {
    expect(INTEL_TCB_INFO.signature.served?.envelope).toBe('json-hex-signature');
    expect(INTEL_TCB_INFO.signature.served?.signatureMember).toBe('signature');
    expect(INTEL_QE_IDENTITY.signature.served?.envelope).toBe('json-hex-signature');
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const read = readOf(weigh(answer.body, answer.chain));
    expect(read.vendorStatus).toBe('UpToDate');
    expect(read.signedAt).toBe(secondsOf(LEVEL_DATE));
    expect(read.validUntil).toBe(secondsOf(NEXT_UPDATE));
    expect(read.declaredCpuType).toBe(FMSPC);
    expect(read.anchorDigest).toBe(vendor.rootDigest);
    expect(read.blobs).toHaveLength(3);
    expect(read.blobs[0]).toEqual(answer.body);
    expect(hex(read.blobs[1] as Uint8Array)).toBe(hex(vendor.issuerDer));
    expect(hex(read.blobs[2] as Uint8Array)).toBe(hex(vendor.rootDer));
  });

  /**
   * The QE Identity arrives under its own member and names no CPU type, so this is the case that says the
   * reader takes the member from the declaration rather than from the body: asked for the TCB Info's member,
   * the same two halves answer with a refusal, and nothing about the bytes distinguishes the two documents.
   */
  it('weighs the QE identity under the member its declaration names, and reads no identity from it', () => {
    const served = servedAnswer(
      qeIdentity({ issueDate: LEVEL_DATE, nextUpdate: NEXT_UPDATE, levels: [{ isvSvn: 0, tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }] }),
      QE_MEMBER,
      vendor,
    );
    const qe = { origin: 'intel-qe-identity' as const, cpuType: null };
    const read = readOf(weigh(served.body, served.chain, INTEL_QE_IDENTITY, qe));
    expect(read.vendorStatus).toBe('UpToDate');
    expect(read.declaredCpuType).toBeNull();
    expect(read.anchorDigest).toBe(vendor.rootDigest);

    const wrongMember = refusalOf(weigh(served.body, served.chain, INTEL_TCB_INFO, qe));
    expect(wrongMember.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(wrongMember.detail).toContain(TCB_MEMBER);
  });

  /**
   * Measured across three routes: the signature holds over the exact span the vendor wrote, while a sorted-key
   * canonicalization of the same parsed member does not verify. Sorted keys are the re-serialization a reader
   * reaches for, so the refusal is pinned here rather than left to be rediscovered.
   */
  it('refuses the same document re-serialized with sorted keys over the signature the vendor wrote', () => {
    const asSent = servedDocument();
    const original = servedMemberText(asSent, TCB_MEMBER);
    const reMade = servedMemberText({ [TCB_MEMBER]: sortedKeys(asSent[TCB_MEMBER] as Record<string, unknown>) }, TCB_MEMBER);
    expect(reMade, 'the sorted text has to differ, or this case proves nothing').not.toBe(original);

    const rewritten = servedWrapperBody(TCB_MEMBER, reMade, servedSignatureMember(original, vendor));
    const refusal = refusalOf(weigh(rewritten, servedChain(vendor)));
    expect(refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusal.detail).toContain(TCB_MEMBER);

    const asAnswered = servedAnswer(asSent, TCB_MEMBER, vendor);
    expect(readOf(weigh(asAnswered.body, asAnswered.chain)).vendorStatus, 'the same key and root over the span as sent').toBe('UpToDate');
  });

  /**
   * The span and not the parsed member: a body whose document member carries its own spacing is weighed over
   * the bytes that arrived, and a reader that re-made the text from the object it parsed would sign-check a
   * different sequence and refuse an answer that is whole. This is the same rule the sorted-key case reads from
   * the other side, and it is the reason the walk returns a substring rather than a stringify.
   */
  it('weighs a body whose member text carries its own spacing, over those bytes and no re-made copy', () => {
    const inner = servedDocument()[TCB_MEMBER] as Record<string, unknown>;
    const spaced = JSON.stringify(inner, null, 1);
    expect(spaced, 'the spaced text has to differ, or this case proves nothing').not.toBe(servedMemberText(servedDocument(), TCB_MEMBER));
    const body = servedWrapperBody(TCB_MEMBER, spaced, servedSignatureMember(spaced, vendor));
    expect(readOf(weigh(body, servedChain(vendor))).vendorStatus).toBe('UpToDate');
  });

  it('refuses a body whose signed span was altered by one byte, and quotes none of what it says', () => {
    const altered = { [TCB_MEMBER]: tcbInfoBody({
      fmspc: FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'LpToDate' }],
    }) };
    const text = servedMemberText(altered, TCB_MEMBER);
    const body = servedWrapperBody(TCB_MEMBER, text, servedSignatureMember(servedMemberText(servedDocument(), TCB_MEMBER), vendor));
    const refusal = refusalOf(weigh(body, servedChain(vendor)));
    expect(refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusal.detail).not.toContain('LpToDate');
  });

  it('refuses a body naming its document member twice, because one would be believed and the other read', () => {
    const text = servedMemberText(servedDocument(), TCB_MEMBER);
    const body = new TextEncoder().encode(`{"${TCB_MEMBER}":${text},"${TCB_MEMBER}":{},"signature":"${servedSignatureMember(text, vendor)}"}`);
    const refusal = refusalOf(weigh(body, servedChain(vendor)));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain(`carries ${TCB_MEMBER} twice`);
  });

  /**
   * A chain that ends at a self-signed name nothing was pinned for and a chain wearing a pinned name over a
   * key the pin does not hold are different failures. The second states how far the walk climbed before it
   * stopped, and neither answer is read as a statement about a platform.
   */
  it('refuses a chain that reaches no root the caller named, and names where it stopped', () => {
    const stranger = testVendor({ rootName: 'Unrelated Root', issuerName: 'Unrelated CA' });
    const elsewhere = servedAnswer(servedDocument(), TCB_MEMBER, stranger);
    const unpinned = refusalOf(weigh(elsewhere.body, elsewhere.chain));
    expect(unpinned.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(unpinned.detail).toContain('pinned nothing');

    // A leaf one vendor signed and a certificate of the same name from another: the walk climbs to the first
    // thing that reads as the issuer and stops at hop 0, because that thing did not sign the leaf.
    const other = testVendor();
    const mixed = servedAnswer(servedDocument(), TCB_MEMBER, other);
    const borrowed = refusalOf(weigh(mixed.body, servedChainOf([other.issuerDer, vendor.rootDer])));
    expect(borrowed.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(borrowed.detail).toContain('certificate 0');

    // The same distinguished names over different keys all the way down, so the walk reaches a name the caller
    // did pin and finds the certificate wearing it is not the one the pin holds.
    const lookalike = refusalOf(weigh(mixed.body, mixed.chain));
    expect(lookalike.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(lookalike.detail).toContain('that pinned copy');
  });

  /**
   * Absence at the fetch is not absence of the document: the body arrived and the pair it belongs to did not.
   * The refusal names the header that carried nothing and quotes what the body states beside it, quoted as the
   * outside text it is, because the walk that would have established those words had no certificates to walk.
   */
  it('refuses to weigh a served document whose chain did not arrive, and says what the body states', () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const refusal = refusalOf(weigh(answer.body, null));
    expect(refusal.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(refusal.detail).toContain(TCB_HEADER);
    expect(refusal.detail).toContain('UpToDate');
    expect(refusal.detail).toContain(FMSPC);

    const bare = refusalOf(weigh(servedWrapperBody(TCB_MEMBER, JSON.stringify({ fmspc: FMSPC }), servedSignatureMember(servedMemberText(servedDocument(), TCB_MEMBER), vendor)), null));
    expect(bare.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(bare.detail).toContain('states no document this path reads');
  });

  /**
   * The vendor sends the pair as raw hex and the curve wants DER, so the reader converts. A signature in the
   * DER spelling is a real signature over the real span, and it is refused: the width this envelope states is
   * the rule, and a reader that took either spelling would accept a shape the origin never answers with.
   */
  it('refuses a signature member that is not the raw pair this envelope states, and throws on none of it', () => {
    const text = servedMemberText(servedDocument(), TCB_MEMBER);
    const der = hex(p256.sign(sha256(new TextEncoder().encode(text)), vendor.signingKey).toDERRawBytes());
    expect(der.length, 'a DER pair is wider than the served spelling').not.toBe(128);
    for (const spelling of [der, 'AB'.repeat(64), 'ab'.repeat(63), 'zz'.repeat(64)]) {
      const refusal = refusalOf(weigh(servedWrapperBody(TCB_MEMBER, text, spelling), servedChain(vendor)));
      expect(refusal.code, spelling.slice(0, 12)).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusal.detail).toContain('signature');
    }
  });

  /**
   * A pair whose numbers are outside the curve order is nothing this curve can be handed, and the conversion
   * this path reuses is what turns that into a refusal rather than an exception from inside the arithmetic.
   */
  it('refuses a raw pair outside the curve order instead of throwing from the curve', () => {
    const text = servedMemberText(servedDocument(), TCB_MEMBER);
    const tail = servedSignatureMember(text, vendor).slice(64);
    for (const outOfRange of [`${'0'.repeat(64)}${tail}`, `${'f'.repeat(64)}${tail}`]) {
      const refusal = refusalOf(weigh(servedWrapperBody(TCB_MEMBER, text, outOfRange), servedChain(vendor)));
      expect(refusal.code, outOfRange.slice(0, 8)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
      expect(refusal.detail, outOfRange.slice(0, 8)).toContain('outside the range this curve signs in');
    }
  });

  it('refuses a chain header that is no text, is not URL-encoded, or decodes to no certificate', () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const met = [
      [new Uint8Array([0xff, 0xfe, 0x00]), 'is not UTF-8 text'],
      [new TextEncoder().encode('%E0%A4%A'), 'is not URL-encoded text'],
      [new TextEncoder().encode('no certificates here'), 'holds no certificate that parses'],
    ] as const;
    for (const [spelling, why] of met) {
      const refusal = refusalOf(weigh(answer.body, spelling));
      expect(refusal.code, new TextDecoder().decode(spelling)).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusal.detail, why).toContain(TCB_HEADER);
      expect(refusal.detail, why).toContain(why);
    }
  });

  /**
   * The wrapper is the envelope: text that is no object, an object that is an array, and a signature member
   * that is a number are each a refusal about the answer rather than a fault in the caller, and none of them
   * reaches the curve.
   */
  it('refuses a body that is not the JSON wrapper this envelope states', () => {
    const text = servedMemberText(servedDocument(), TCB_MEMBER);
    // Spelled by hand rather than by the writer, because the writer quotes its signature member and this member
    // is not a string at all: a number between braces is what a wrapper that is nearly right looks like.
    const numeric = new TextEncoder().encode(`{"${TCB_MEMBER}":${text},"signature":1234}`);
    const met = [
      [new TextEncoder().encode('this is not a wrapper'), 'is not a JSON object'],
      [new TextEncoder().encode('[1,2,3]'), 'is not a JSON object'],
      [numeric, 'not spelled as a JSON string'],
    ] as const;
    for (const [body, why] of met) {
      const refusal = refusalOf(weigh(body, servedChain(vendor)));
      expect(refusal.code, new TextDecoder().decode(body).slice(0, 24)).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusal.detail, why).toContain(why);
    }
  });

  it('weighs no served answer for a declaration that names no document member', () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const unnamed: OriginDeclaration = { ...INTEL_TCB_INFO, window: { ...INTEL_TCB_INFO.window, documentMember: null } };
    const refusal = refusalOf(weigh(answer.body, answer.chain, unnamed));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('names none');
  });

  it('weighs no served answer for a declaration that names no served envelope', () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const alone: OriginDeclaration = { ...INTEL_TCB_INFO, signature: { ...INTEL_TCB_INFO.signature, served: null } };
    expect(alone.chainHeader, 'the header is named, so a chain does reach this reader').toBe(TCB_HEADER);
    const refusal = refusalOf(weigh(answer.body, answer.chain, alone));
    expect(refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusal.detail).toContain('names no served envelope');
  });
});

describe('the one caller that asks the origin', () => {
  /**
   * Which arm weighs the answer is the declaration's fact and the answer's, never a guess from the bytes. This
   * is the fetched path weighing a served pair, and the reach it settles is the reach a fetched answer has
   * always owed: observed by this run, standing for the moment asked about.
   */
  it('weighs an answer that arrived with its chain, and keeps the reach a fetched answer owes', async () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const outcome = await ask(answering(answer.body, answer.chain));
    if (outcome.state !== 'current') {
      throw new Error(`the served answer answered ${outcome.state}: ${'refusal' in outcome ? outcome.refusal.detail : ''}`);
    }
    expect(outcome.collateral.digest).toBe(hex(sha256(answer.body)));
    expect(outcome.collateral.anchorDigest).toBe(vendor.rootDigest);
    expect(outcome.collateral.blobs).toHaveLength(3);
    expect(outcome.collateral.declared.vendorStatus).toBe('UpToDate');
    expect(outcome.claim.reach).toBe('current-knowledge');
    expect(outcome.claim.observedAt).toBe(OBSERVED);
  });

  /**
   * A body that arrived without its header is a body alone, and the arm that reads a body alone keeps its
   * certificates inside it. That is the refusal `read.test.ts` pins for exactly this shape, so the appraise
   * path owes the same answer about the same bytes rather than a second one.
   */
  it('leaves a served body that arrived alone to the arm that reads a body alone', async () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    for (const outcome of [
      await ask(answering(answer.body, null)),
      await ask(async () => new Response('bytes'), { retained: { bytes: answer.body, observedAt: OBSERVED } }),
    ]) {
      expect(outcome.state).toBe('unavailable');
      if ('refusal' in outcome) {
        expect(outcome.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');
        expect(outcome.refusal.detail).toContain('not the three a JWS has');
      }
    }
  });

  it('says stale about a served answer whose window has closed, and keeps the bytes it weighed', async () => {
    const answer = servedAnswer(servedDocument(), TCB_MEMBER, vendor);
    const outcome = await ask(answering(answer.body, answer.chain), { appraisalAt: AFTER });
    expect(outcome.state).toBe('stale');
    if ('refusal' in outcome) {
      expect(outcome.refusal.code).toBe('COLLATERAL_WINDOW_CLOSED');
    }
    expect(outcome.collateral?.classification.window).toEqual({ from: secondsOf(LEVEL_DATE), until: secondsOf(NEXT_UPDATE) });
    expect(outcome.collateral?.anchorDigest).toBe(vendor.rootDigest);
  });

  it('reports a vendor revocation out of a served answer, the same answer the JWS arm would have read', async () => {
    const answer = servedAnswer(servedDocument('OutOfDate'), TCB_MEMBER, vendor);
    const outcome = await ask(answering(answer.body, answer.chain));
    expect(outcome.state).toBe('revoked');
    expect(outcome.collateral?.classification.readAs).toBe('revoked');
  });

  it('refuses a served answer covering another identity than the one asked, before its words are read', async () => {
    const answer = servedAnswer(
      tcbInfo({ fmspc: '00A0F0000000', issueDate: LEVEL_DATE, nextUpdate: NEXT_UPDATE, levels: [{ tcbDate: LEVEL_DATE, tcbStatus: 'UpToDate' }] }),
      TCB_MEMBER,
      vendor,
    );
    const outcome = await ask(answering(answer.body, answer.chain));
    expect(outcome.state).toBe('unavailable');
    if ('refusal' in outcome) {
      expect(outcome.refusal.code).toBe('COLLATERAL_IDENTITY_MISMATCH');
      expect(outcome.refusal.detail).toContain('00A0F0000000');
    }
  });
});

/**
 * Members and the objects under them, in sorted order: the one re-serialization this package must not reach
 * for, written here so the case above can show that it fails.
 */
function sortedKeys(value: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    const member = value[key];
    out[key] = typeof member === 'object' && member !== null && !Array.isArray(member)
      ? sortedKeys(member as Record<string, unknown>)
      : Array.isArray(member)
        ? member.map((one) => (typeof one === 'object' && one !== null && !Array.isArray(one) ? sortedKeys(one as Record<string, unknown>) : one))
        : member;
  }
  return out;
}
