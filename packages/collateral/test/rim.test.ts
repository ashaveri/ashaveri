import { describe, expect, it } from 'vitest';
import {
  INTEL_PCK_CRL,
  INTEL_TCB_INFO,
  NVIDIA_RIM,
  ORIGIN_DECLARATIONS,
  appraiseCollateral,
  collateralCacheKey,
  declarationFor,
  readRimManifest,
  requestUrl,
  type CollateralErrorCode,
  type CollateralQuery,
  type CollateralRefusal,
  type CollateralTransport,
  type RimReadOutcome,
} from '../src/index.js';
import { sha256Hex } from '../src/bytes.js';
import { opaqueManifest, writeRimWrapper } from './rim-writer.js';

/**
 * What the RIM wrapper reader answers, and what it refuses.
 *
 * The wrapper is the half of a RIM answer this package can weigh: it carries the manifest bytes and the digest
 * the same body names for them, so a reader can say which manifest the service answered with, in which format it
 * says the manifest is, and whether the bytes are the ones the wrapper meant. That is a statement about an
 * answer, not about a device, and the suite reads the pairing that says so: every wrapper that parses comes back
 * with the refusal beside it, because the manifest's own signature is taken over a canonicalized element and no
 * canonicalization exists in this package's dependency set.
 *
 * No bytes of anybody's served RIM are here. The wrapper is written by `rim-writer.ts` from the member names
 * cited beside the declaration, and the manifest inside it is an opaque labelled run of bytes rather than a
 * document this repository makes up, because spelling SWID elements out here would be inventing the vendor's
 * field names while testing nothing the reader weighs.
 */

const RIM_ID = 'NVIDIA-SBIOS-gpu-rim-0001';

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'nvidia-rim',
    platform: 'sgx',
    cpuType: null,
    level: null,
    rimId: RIM_ID,
    appraisalAt: 1790000000,
    roots: [new Uint8Array([1])],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function read(body: Uint8Array, over: Partial<CollateralQuery> = {}): RimReadOutcome {
  return readRimManifest(body, query(over), NVIDIA_RIM);
}

/** The refusal of an outcome that has one, whether or not it also carries a read. */
function refusalOf(outcome: RimReadOutcome): CollateralRefusal {
  if (!('refusal' in outcome)) {
    throw new Error('the answer carried no refusal');
  }
  return outcome.refusal;
}

function codeOf(outcome: RimReadOutcome): CollateralErrorCode {
  return refusalOf(outcome).code;
}

function silence(): CollateralTransport {
  return async () => {
    throw new Error('a transport was asked');
  };
}

describe('the RIM wrapper reader', () => {
  it('reads the wrapper a route answers with and pairs the read with the signature it did not weigh', () => {
    const manifest = opaqueManifest();
    const outcome = read(writeRimWrapper({ id: RIM_ID }));
    if (!('read' in outcome)) {
      throw new Error(`the wrapper was refused: ${refusalOf(outcome).detail}`);
    }
    expect(outcome.read.id).toBe(RIM_ID);
    expect(outcome.read.format).toBe('TCG');
    expect(outcome.read.lastUpdated).toBe('2026-09-01T00:00:00Z');
    expect(outcome.read.rim).toEqual(manifest);
    expect(outcome.read.digest).toBe(sha256Hex(manifest));
    expect(outcome.read.blobs).toHaveLength(1);
    expect(outcome.refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(outcome.refusal.detail).toContain('canonicalized');
    expect(outcome.refusal.detail).toContain('TCG');
  });

  it('keeps the manifest bytes as the wrapper carried them and hashes them as they arrived', () => {
    const manifest = new Uint8Array(Array.from({ length: 300 }, (_one, index) => index % 251));
    const outcome = read(writeRimWrapper({ rim: manifest, id: RIM_ID }));
    if (!('read' in outcome)) throw new Error('the wrapper was refused');
    expect(outcome.read.rim).toEqual(manifest);
    expect(outcome.read.digest).toBe(sha256Hex(manifest));
    expect(outcome.refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });

  it('refuses a wrapper whose manifest is not the bytes its own digest names', () => {
    const outcome = read(writeRimWrapper({ digest: sha256Hex(new Uint8Array([1, 2, 3])) }));
    expect(codeOf(outcome)).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect('read' in outcome).toBe(false);
    expect(refusalOf(outcome).detail).toContain('hashes to');
  });

  it('names the manifest the answer carries when it is not the one the question asked for', () => {
    const outcome = read(writeRimWrapper({ id: 'NVIDIA-SBIOS-another-rim' }));
    expect(codeOf(outcome)).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusalOf(outcome).missing).toEqual(['rimId']);
    expect(refusalOf(outcome).detail).toContain('NVIDIA-SBIOS-another-rim');
  });

  it('carries no id comparison when the question names none, because nothing was stated to compare against', () => {
    const outcome = read(writeRimWrapper({ id: 'whatever-rim' }), { rimId: null });
    if (!('read' in outcome)) throw new Error(`a question naming no id was refused at the identity: ${refusalOf(outcome).detail}`);
    expect(outcome.read.id).toBe('whatever-rim');
  });

  it('refuses a format name outside the three the reference states rather than sorting it into one', () => {
    const outcome = read(writeRimWrapper({ format: 'SWID' }));
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(refusalOf(outcome).detail).toContain('SWID');
    expect(refusalOf(outcome).detail).toContain('TCG, CORIM, GENERIC');
  });

  it('refuses a wrapper that carries no member the reader reads, one member at a time', () => {
    for (const member of ['id', 'rim_format', 'last_updated', 'rim', 'sha256']) {
      const outcome = read(writeRimWrapper({ omit: [member] }));
      expect(codeOf(outcome), member).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusalOf(outcome).detail, member).toContain(member);
    }
  });

  it('refuses a member that is present but not the text the wrapper states it as', () => {
    for (const member of ['id', 'rim_format', 'last_updated', 'rim', 'sha256']) {
      const outcome = read(writeRimWrapper({ notText: [member] }));
      expect(codeOf(outcome), member).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusalOf(outcome).detail, member).toContain(member);
    }
  });

  it('refuses a digest that is not a sha256 and a manifest that is not base64, as shapes rather than as mismatches', () => {
    const short = read(writeRimWrapper({ digest: 'abcd' }));
    expect(codeOf(short)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(short).detail).toContain('64 hex characters');

    const wrapped = read(writeRimWrapper({ rimText: 'data:application/xml;base64,AAAA' }));
    expect(codeOf(wrapped)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(wrapped).detail).toContain('base64');
  });

  it('refuses a body that is not a wrapper at all, and one that is not text', () => {
    for (const body of [writeRimWrapper({ raw: 'not json' }), writeRimWrapper({ raw: '[1,2]' }), Uint8Array.from([0x30, 0x82, 0xff])]) {
      const outcome = read(body);
      expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    }
    const empty = read(new Uint8Array(0));
    expect(codeOf(empty)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(empty).detail).toContain('empty');

    const oversize = read(writeRimWrapper({ rim: new Uint8Array(NVIDIA_RIM.maxResponseBytes + 1) }));
    expect(codeOf(oversize)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(refusalOf(oversize).detail).toContain(String(NVIDIA_RIM.maxResponseBytes));
  });

  it('refuses the wrapper of an origin whose answer it is not, naming the shape that arrived', () => {
    for (const declaration of [INTEL_TCB_INFO, INTEL_PCK_CRL, ORIGIN_DECLARATIONS['amd-kds']]) {
      const outcome = readRimManifest(writeRimWrapper(), query({ origin: declaration.name }), declaration);
      // An origin with a reader here is supported, so what this arm cannot weigh is the envelope, and the
      // RIM wrapper itself is the only origin this arm reads at all.
      expect(codeOf(outcome), declaration.name).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(refusalOf(outcome).detail, declaration.name).toContain(declaration.answer);
    }
  });

  /**
   * The declaration states both halves of the reading: the wrapper a reader here weighs, and the signature no
   * reader here weighs. The origin is served because an arm reads its answer, and it reaches no verdict because
   * the reading stops there, so a caller of `declarationFor` holding this declaration has to learn the stop from
   * the reader's own sentence rather than from the absence of a reader.
   */
  it('states the wrapper as read and the manifest as unread on the declaration itself', () => {
    expect(NVIDIA_RIM.reader.as).toBe('rim-wrapper');
    expect(NVIDIA_RIM.reader.reads).toContain('readRimManifest');
    expect(NVIDIA_RIM.reader.reads).toContain('sha256');
    expect(NVIDIA_RIM.reader.lacks).toContain('XML digital-signature reader');
    const asked = declarationFor('nvidia-rim');
    expect('refusal' in asked).toBe(false);
    expect('refusal' in asked ? 'refusal' : asked.reader.as).toBe('rim-wrapper');
  });
});

describe('the appraisal path over the RIM', () => {
  /**
   * The wrapper reader is a reader of an answer, not an appraisal: a manifest this package cannot sign-check
   * answers no verdict, so the platform-level entry point names the arm that reads the wrapper and the reading it
   * has no rule for, rather than handing a wrapper back as if it were a statement about a device. The refusal is
   * the missing-context one because the appraisal is missing the reading, not the origin: nothing was asked, and
   * no state carrying bytes or a claim is reachable for this origin through that entry point.
   */
  it('refuses an appraisal of the RIM before anything is asked of the origin', async () => {
    const outcome = await appraiseCollateral(query(), { transport: silence() });
    expect(outcome.state).toBe('missing-context');
    if (!('refusal' in outcome)) throw new Error('the RIM answered with a verdict it cannot reach');
    expect(outcome.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(outcome.refusal.detail).toContain('XML digital-signature reader');
    expect(outcome.refusal.detail).toContain('readRimManifest');
    expect(outcome.refusal.missing).toEqual(['level']);
    expect(outcome.collateral).toBeNull();
    expect(outcome.claim).toBeNull();
  });

  it('names the id a RIM address cannot be built without, and spells the route when it is given', () => {
    const missing = requestUrl(query({ rimId: null }), NVIDIA_RIM);
    if (typeof missing === 'string') throw new Error('a RIM address was spelled without an id');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['rimId']);
    expect(requestUrl(query({ rimId: 'gpu rim/0001' }), NVIDIA_RIM)).toBe(
      'https://rim.attestation.nvidia.com/v1/rim/gpu%20rim%2F0001',
    );
  });

  it('states no record for a kept manifest, because no reader states the identity and window it belongs to', () => {
    const key = collateralCacheKey(query(), NVIDIA_RIM);
    if (typeof key === 'string') throw new Error('a kept RIM was keyed without a verdict to answer for');
    expect(key.missing).toEqual([]);
    expect(key.why).toContain('no cache key yet');
  });
});
