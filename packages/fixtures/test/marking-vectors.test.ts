import { describe, expect, it } from 'vitest';
import {
  MARKING_SCHEMES,
  extractMarkedRegion,
  fromBase64Url,
  hashRequest,
  toBase64Url,
  toHex,
  verifyReceipt,
  type MarkingScheme,
  type ReceiptPayloadV2,
} from '@ashaveri/receipt';
import {
  loadFixtureKey,
  loadMarkingVectors,
  loadReceiptFixture,
  type MarkingVector,
} from '../src/index.js';

/**
 * The published marked-region vectors, replayed the way a port replays them: read the response bytes,
 * locate a region with the rule the label names, hash it, and compare. Nothing here reaches into the
 * fixtures to check them against themselves: the file states a span and a digest, and the only
 * question is whether the rule this repository publishes produces that answer for those bytes.
 *
 * The refusals matter as much as the two accepted cases. A stripped region and a duplicated one are
 * both refusals and both `MARK_MISMATCH`, and a port that resolves an ambiguous response by picking a
 * candidate has implemented a rule no document states, which is the confusion the registry exists to
 * refuse.
 */

const file = loadMarkingVectors();
const CLOCK = 1_772_000_000;

function vectorNamed(name: string): MarkingVector {
  const found = file.vectors.find((each) => each.name === name);
  if (found === undefined) throw new Error(`marking-v1.json publishes no ${name} case`);
  return found;
}

/**
 * What a verifier holding these bytes answers: the digest of the region the rule locates, compared
 * against the `d` the receipt carries. A refusal to locate one region is the same verdict by the same
 * code, which is what the published row says and what this checks rather than assumes.
 */
function verdict(one: MarkingVector): 'verify-ok' | 'MARK_MISMATCH' {
  try {
    const region = extractMarkedRegion(one.sch as MarkingScheme, fromBase64Url(one.responseBase64Url));
    return toHex(hashRequest(region)) === one.dHex ? 'verify-ok' : 'MARK_MISMATCH';
  } catch {
    return 'MARK_MISMATCH';
  }
}

describe('the marked-region vectors', () => {
  it('publish the schemes the registry names, and no others', () => {
    expect(file.rule.schemes).toEqual([...MARKING_SCHEMES]);
    expect(file.rule.digestField).toBe('mk.d');
    expect(file.rule.registry).toBe('docs/receipt-spec.md section 3.3');
  });

  it('answer as each case promises, on both shapes and for both labels', () => {
    const outcomes = file.vectors.map((one) => `${one.name}: ${verdict(one)}`);
    const promised = file.vectors.map((one) => `${one.name}: ${one.expected}`);
    expect(outcomes).toEqual(promised);
    expect(new Set(file.vectors.map((one) => one.sch))).toEqual(new Set(['none', 'provenance-v1']));
    expect(new Set(file.vectors.map((one) => one.shape))).toEqual(new Set(['buffered', 'streamed']));
  });

  it('state the span a reader locates, not merely that one exists', () => {
    for (const one of file.vectors) {
      let located: string | null;
      try {
        located = toBase64Url(extractMarkedRegion(one.sch as MarkingScheme, fromBase64Url(one.responseBase64Url)));
      } catch {
        located = null;
      }
      expect(`${one.name}: ${String(located)}`, 'which span the rule finds').toBe(
        `${one.name}: ${String(one.foundRegionBase64Url)}`,
      );
      if (one.foundRegionBase64Url !== null) {
        expect(fromBase64Url(one.foundRegionBase64Url).length).toBe(one.foundRegionByteLength);
      }
    }
  });

  it('publish byte counts that agree with the bytes they carry', () => {
    for (const one of file.vectors) {
      expect(fromBase64Url(one.responseBase64Url).length, `${one.name} response`).toBe(one.responseByteLength);
      expect(fromBase64Url(one.attestedRegionBase64Url).length, `${one.name} attested region`).toBe(
        one.attestedRegionByteLength,
      );
      expect(toHex(hashRequest(fromBase64Url(one.attestedRegionBase64Url))), `${one.name} dHex`).toBe(one.dHex);
    }
  });

  it('digest the empty region for `none`, so the absence is a value and not an omission', () => {
    const declared = vectorNamed('absence-declared');
    expect(declared.attestedRegionByteLength).toBe(0);
    expect(declared.dHex).toBe(toHex(hashRequest(new Uint8Array(0))));
    // The same attestation over a response that does carry a mark is the refusal a deployment that
    // marks nothing meets from a backend that marks its own output.
    expect(vectorNamed('absence-declared-over-marked').dHex).toBe(declared.dHex);
    expect(vectorNamed('absence-declared-over-marked').expected).toBe('MARK_MISMATCH');
  });

  it('cover the substituted mark, which is the case the response digest cannot see', () => {
    const substituted = vectorNamed('region-substituted');
    expect(substituted.foundRegionBase64Url).not.toBeNull();
    expect(substituted.foundRegionBase64Url).not.toBe(substituted.attestedRegionBase64Url);
    // One whole response, one field of one member apart, and both spans published beside it.
    expect(substituted.responseByteLength).toBe(vectorNamed('buffered-member').responseByteLength);
  });

  it('refuse an ambiguous response in both shapes rather than resolve it', () => {
    for (const name of ['region-duplicated', 'streamed-region-duplicated']) {
      const one = vectorNamed(name);
      expect(one.foundRegionBase64Url, `${name} has no single region`).toBeNull();
      expect(one.expected).toBe('MARK_MISMATCH');
    }
  });

  it('are the same bytes the v2 receipt fixture attests, pair for pair', () => {
    // The two suites publish one fact about one response: `marking-v1.json` states the region and its
    // digest, and the receipt fixture signs a document whose `res` covers the whole body and whose
    // `mk.d` covers the span inside it. A generator that drifted on either side would disagree here.
    const buffered = vectorNamed('buffered-member');
    const verified = verifyReceipt(loadReceiptFixture('receipt-marked-v2').bytes, {
      publicKey: loadFixtureKey().publicKey,
      now: CLOCK,
    });
    expect(verified.payload.v).toBe(2);
    const payload = verified.payload as ReceiptPayloadV2;
    expect(payload.mk.sch).toBe(buffered.sch);
    expect(toHex(payload.res)).toBe(toHex(hashRequest(fromBase64Url(buffered.responseBase64Url))));
    expect(toHex(payload.mk.d)).toBe(buffered.dHex);
  });
});
