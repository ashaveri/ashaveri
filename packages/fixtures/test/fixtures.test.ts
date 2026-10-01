import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ReceiptError,
  decodeReceipt,
  extractMarkedRegion,
  frameResponse,
  hashRequest,
  toBase64Url,
  toHex,
  verifyReceipt,
} from '@ashaveri/receipt';
import {
  loadFixtureKey,
  loadManifest,
  loadMarkingVectors,
  loadReceiptFixture,
  loadResVectors,
  type ReceiptFixtureRow,
} from '../src/index.js';

// FIXED_NOW is whole seconds since the Unix epoch: it equals the published receipts' `iat` and is
// handed to `verifyReceipt` as `nowSeconds`, which the freshness windows compare against `iat`.
const FIXED_NOW = 1_772_000_000;

function errorCode(fn: () => unknown): string | 'no-error' {
  try {
    fn();
    return 'no-error';
  } catch (e) {
    return (e as ReceiptError).code;
  }
}

/** The refusal a reader gave, with its sentence: the position a row states is checked against this. */
function refusal(fn: () => unknown): { code: string; message: string } {
  try {
    fn();
    return { code: 'verify-ok', message: '' };
  } catch (e) {
    if (e instanceof ReceiptError) return { code: e.code, message: e.message };
    throw e;
  }
}

const bytesOf = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));
const encode = (value: string): Uint8Array => new TextEncoder().encode(value);

/** The rows stating a version, which is the population each per-column check below selects from. */
const columned = (): ReceiptFixtureRow[] => loadManifest().fixtures.filter((entry) => entry.v !== undefined);

/** One row by name, with the receipt its own entry points at read beside it. */
function rowOf(name: string): ReceiptFixtureRow & { receipt: Uint8Array; responseBytes: Uint8Array } {
  const entry = loadManifest().fixtures.find((each) => each.name === name);
  if (entry === undefined) throw new Error(`manifest.json states no row named ${name}`);
  if (entry.responseBase64Url === undefined) throw new Error(`${name} states no response bytes to read`);
  return {
    ...entry,
    receipt: loadReceiptFixture(name).bytes,
    responseBytes: bytesOf(entry.responseBase64Url),
  };
}

/**
 * The published bytes a row's `response` column names, read out of the suite that holds them.
 *
 * A receipt attests a response and this package publishes that response elsewhere, so the two files are
 * one fact: the row that disagreed with the suite it names would be a vector and a byte string that no
 * reader can put together.
 */
function publishedNamed(as: string): Uint8Array {
  const [file, rest] = as.split('#');
  if (file === 'marking-v1.json' && rest !== undefined) {
    const found = loadMarkingVectors().vectors.find((each) => each.name === rest);
    if (found === undefined) throw new Error(`${as} names no vector of marking-v1.json`);
    return bytesOf(found.responseBase64Url);
  }
  if (file === 'res-v1.json' && rest !== undefined) {
    const key = rest.startsWith('framing.') ? rest.slice('framing.'.length) : rest;
    const framing = loadResVectors().framing as unknown as Record<string, string>;
    const piece = framing[key];
    if (piece === undefined) throw new Error(`${as} names no framing field res-v1.json states`);
    return encode(piece);
  }
  throw new Error(`${as} is a published piece this reader does not know how to reach`);
}

/** One piece of an assembled row, where `.region` asks for the span rather than the whole response. */
function publishedPiece(as: string): Uint8Array {
  const [file, rest] = as.split('#');
  if (rest !== undefined && rest.endsWith('.region') && file === 'marking-v1.json') {
    const name = rest.slice(0, -'.region'.length);
    const found = loadMarkingVectors().vectors.find((each) => each.name === name);
    if (found?.foundRegionBase64Url === null || found === undefined) {
      throw new Error(`${as} names a row with no located region to join`);
    }
    return bytesOf(found.foundRegionBase64Url);
  }
  return publishedNamed(as);
}

describe('golden fixtures', () => {
  it('valid receipt fixture verifies against the fixture key', () => {
    const fixture = loadReceiptFixture('receipt-valid-v1');
    const key = loadFixtureKey();
    const verified = verifyReceipt(fixture.bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.mdl).toBe('meta-llama/Llama-3.1-8B-Instruct');
    expect(verified.payload.tok).toEqual({ p: 128, c: 64 });
  });

  it('software receipt fixture verifies and makes no TEE claim', () => {
    const fixture = loadReceiptFixture('receipt-software-v1');
    const key = loadFixtureKey();
    const verified = verifyReceipt(fixture.bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
    expect(verified.payload.meas.tee).toBe('software');
    expect(verified.payload.meas.m).toHaveLength(32);
  });

  it('every fixture is the bytes its entry digests', () => {
    const manifest = loadManifest();
    expect(manifest.version).toBe(1);
    expect(manifest.fixtures.length).toBeGreaterThan(0);
    // The count is read rather than repeated: a row whose file moved and a file no row names are the
    // two ways this suite comes apart, and both are caught by walking the entries and the names.
    const files = new Set(manifest.fixtures.map((entry) => entry.path));
    expect(files.size).toBe(manifest.fixtures.length);
    for (const entry of manifest.fixtures) {
      const fixture = loadReceiptFixture(entry.name);
      expect(toHex(fixture.digest), `${entry.name} digest`).toBe(entry.digestSha256);
    }
  });

  it('every shipped vector behaves as its manifest entry promises', () => {
    const key = loadFixtureKey();
    for (const entry of loadManifest().fixtures) {
      const fixture = loadReceiptFixture(entry.name);
      const outcome = errorCode(() => verifyReceipt(fixture.bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      const observed = outcome === 'no-error' ? 'verify-ok' : outcome;
      expect(`${entry.name}: ${observed}`).toBe(`${entry.name}: ${entry.expected}`);
    }
  });

  it('tampered fixture fails with INVALID_SIGNATURE', () => {
    const fixture = loadReceiptFixture('receipt-tampered-v1');
    const key = loadFixtureKey();
    try {
      verifyReceipt(fixture.bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW });
      throw new Error('expected ReceiptError');
    } catch (e) {
      expect((e as ReceiptError).code).toBe('INVALID_SIGNATURE');
    }
  });

  it('valid fixture honors nonce and freshness options', () => {
    const fixture = loadReceiptFixture('receipt-valid-v1');
    const key = loadFixtureKey();
    const nonce = JSON.parse(
      JSON.stringify(loadReceiptFixture('receipt-valid-v1').json?.payload.nce ?? ''),
    ) as string;
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
    const options = {
      publicKey: key.publicKey,
      expectedNonce: new Uint8Array(Buffer.from(nonce, 'hex')),
      nowSeconds: FIXED_NOW,
      freshnessSeconds: 3600,
      evidenceFreshnessSeconds: 3600,
    };
    expect(() => verifyReceipt(fixture.bytes, options)).not.toThrow();
  });
});

describe('the verdicts a receipt row states, read by both shipped readers', () => {
  it('gives the keyless reader the answer each row states beside it', () => {
    // `decodeReceipt` signs nothing and checks nothing: it reads the payload a document claims. A row
    // that refused only with a key in hand would be refusing for authenticity, and every refusal row
    // here is one that answers the same way both ways, which is what the two columns say out loud.
    const stated = columned().filter((entry) => entry.keyless !== undefined);
    expect(stated.length).toBeGreaterThan(0);
    for (const entry of stated) {
      const observed = errorCode(() => decodeReceipt(loadReceiptFixture(entry.name).bytes));
      expect(`${entry.name}: ${observed === 'no-error' ? 'verify-ok' : observed}`).toBe(
        `${entry.name}: ${entry.keyless}`,
      );
    }
  });

  it('names in the refusal itself the position the row states', () => {
    // The rule is not restated here: the shipped reader's own sentence is asked which member it choked
    // on, and a row pointing at a position no refusal names is a row nothing refuses for.
    const refusing = columned().filter((entry) => entry.fault !== undefined);
    expect(refusing.length).toBeGreaterThan(0);
    const key = loadFixtureKey();
    for (const entry of refusing) {
      const given = refusal(() => verifyReceipt(loadReceiptFixture(entry.name).bytes, { publicKey: key.publicKey, nowSeconds: FIXED_NOW }));
      expect(given.code, `${entry.name} code`).toBe(entry.expected);
      const fault = entry.fault!;
      expect(given.message, `${entry.name} names no ${fault.at}`).toContain(fault.at);
      if (fault.member !== undefined) {
        expect(given.message, `${entry.name} quotes no ${fault.member}`).toContain(fault.member);
      }
    }
  });
});

describe('what a receipt row states about the bytes it attests', () => {
  it('attests the response the published piece it names holds', () => {
    const rows = columned().filter((entry) => entry.responseBase64Url !== undefined);
    expect(rows.length).toBeGreaterThan(0);
    for (const entry of rows) {
      const held = bytesOf(entry.responseBase64Url!);
      expect(held, `${entry.name} byte length`).toHaveLength(entry.responseByteLength!);
      if (entry.assembledFrom !== undefined) {
        // An assembled row is its published pieces in the order the row states them, and nothing else.
        const joined = new Uint8Array(
          entry.assembledFrom.reduce((total, piece) => total + publishedPiece(piece).length, 0),
        );
        let at = 0;
        for (const piece of entry.assembledFrom) {
          joined.set(publishedPiece(piece), at);
          at += publishedPiece(piece).length;
        }
        expect(toHex(held), `${entry.name} assembled`).toBe(toHex(joined));
        continue;
      }
      expect(toHex(held), `${entry.name} names ${entry.response}`).toBe(toHex(publishedNamed(entry.response!)));
    }
  });

  it('digests the whole response and each of its items out of those same bytes', () => {
    const rows = columned().filter((entry) => entry.items !== undefined && entry.items.length > 0);
    expect(rows.length).toBeGreaterThan(0);
    for (const entry of rows) {
      const held = bytesOf(entry.responseBase64Url!);
      if (entry.expected === 'verify-ok') {
        expect(toHex(hashRequest(held)), `${entry.name} res`).toBe(
          toHex(decodeReceipt(loadReceiptFixture(entry.name).bytes).payload.res),
        );
      }
      const framing = frameResponse(entry.contentType!, held);
      if (!framing.framed) throw new Error(`${entry.name} states items over bytes that frame none`);
      // The list the row states is the list the shipped reader of a response body gives these bytes,
      // item for item and byte for byte, so an item digest is checkable and not asserted. This reaches
      // the refused rows too: a refusal about one member is not a refusal about these bytes.
      expect(framing.items, `${entry.name} item count`).toHaveLength(entry.items!.length);
      for (const [index, one] of framing.items.entries()) {
        const stated = entry.items![index]!;
        expect(toHex(one.d), `${entry.name} itm[${index}].d`).toBe(stated.d);
        expect(toBase64Url(one.bytes), `${entry.name} itm[${index}] bytes`).toBe(stated.bytesBase64Url);
        expect(one.bytes).toHaveLength(stated.byteLength);
        expect(toHex(sha256(bytesOf(stated.bytesBase64Url))), `${entry.name} itm[${index}] of its own bytes`).toBe(
          stated.d,
        );
      }
    }
  });

  it('stamps each item at an instant before the receipt that attests it', () => {
    const rows = columned().filter((entry) => entry.items !== undefined && entry.expected === 'verify-ok');
    expect(rows.length).toBeGreaterThan(0);
    for (const entry of rows) {
      const payload = decodeReceipt(loadReceiptFixture(entry.name).bytes).payload;
      if (payload.v !== 1) throw new Error(`${entry.name} states items and is not a v1 document`);
      let previous = -1;
      for (const [index, one] of payload.itm.entries()) {
        const stated = entry.items![index]!;
        expect(one.t, `${entry.name} itm[${index}].t`).toBe(stated.t);
        // An item of a response is never dated at or after the document attesting it, and the list never
        // runs against the order the array states: both are rules a producer keeps, and a published row
        // that broke either would freeze a state the shipped gateway cannot reach.
        expect(one.t, `${entry.name} itm[${index}].t above iat`).toBeLessThan(payload.iat);
        expect(one.t, `${entry.name} itm[${index}].t below its predecessor`).toBeGreaterThanOrEqual(previous);
        previous = one.t;
      }
    }
  });

  it('attests the marking its bytes came off, read off those bytes by the shipped rule', () => {
    const rows = columned().filter((entry) => entry.marking !== undefined && entry.expected === 'verify-ok');
    expect(rows.length).toBeGreaterThan(0);
    for (const entry of rows) {
      const held = bytesOf(entry.responseBase64Url!);
      const payload = decodeReceipt(loadReceiptFixture(entry.name).bytes).payload;
      if (!('mk' in payload)) throw new Error(`${entry.name} states a marking and names no mk`);
      expect(payload.mk.sch, `${entry.name} mk.sch`).toBe(entry.marking);
      expect(toHex(hashRequest(extractMarkedRegion(payload.mk.sch, held))), `${entry.name} mk.d`).toBe(
        toHex(payload.mk.d),
      );
    }
  });

  it('states the disclosure and the anchor the document carries, in the twin too', () => {
    const rows = columned().filter((entry) => entry.sd !== undefined || entry.cva !== undefined);
    expect(rows.length).toBeGreaterThan(0);
    for (const entry of rows) {
      if (entry.expected !== 'verify-ok') continue;
      const payload = decodeReceipt(loadReceiptFixture(entry.name).bytes).payload;
      if (payload.v !== 1) throw new Error(`${entry.name} states sd or cva and is not v1`);
      expect(payload.sd.name, `${entry.name} sd.name`).toBe(entry.sd!.name);
      expect(payload.sd.uncertaintySeconds, `${entry.name} sd.unc`).toBe(entry.sd!.unc ?? null);
      const twin = loadReceiptFixture(entry.name).json;
      expect(twin, `${entry.name} has no twin to compare its columns against`).not.toBeNull();
      if (twin === null) continue;
      if (twin.payload.v !== 1) throw new Error(`${entry.name} twin is not a v1 projection`);
      expect(twin.payload.sd).toEqual({ name: entry.sd!.name, unc: entry.sd!.unc ?? null });
      expect(twin.payload.cva).toEqual(entry.cva);
      expect(twin.payload.itm).toEqual(entry.items?.map((one) => ({ t: one.t, d: one.d })));
      expect(twin.payload.v).toBe(entry.v);
      expect(twin.payload.res).toBe(toHex(hashRequest(bytesOf(entry.responseBase64Url!))));
    }
  });
});

describe('what a response frames, and what the document says about it', () => {
  it('names the one version the format declares, and states an item list that follows the framing', () => {
    // The version is not an answer about the bytes any more, because the format declares one. What the
    // bytes do answer is the item list: a response that frames items yields one entry per item in
    // framing order, and the entry digests are the shipped framer's own, read off these bytes rather
    // than restated. A row whose bytes frame nothing has no accepted document beside it to compare.
    const issued = columned().filter((entry) => entry.expected === 'verify-ok');
    expect(issued.length).toBeGreaterThan(0);
    for (const entry of issued) {
      const payload = decodeReceipt(loadReceiptFixture(entry.name).bytes).payload;
      expect(payload.v, `${entry.name} version against the one the format declares`).toBe(1);
      const framing = frameResponse(entry.contentType!, bytesOf(entry.responseBase64Url!));
      if (!framing.framed) continue;
      expect(
        payload.itm.map((one) => toHex(one.d)),
        `${entry.name} itm against the digests the shipped framer reads`,
      ).toEqual(framing.items.map((one) => toHex(one.d)));
    }
  });

  it('states both shapes of the stream whose only item is the mark', () => {
    const unmarked = rowOf('receipt-empty-items-v1');
    const marked = rowOf('receipt-marked-sentinel-v1');
    expect([unmarked.v, marked.v]).toEqual([1, 1]);
    // One upstream body, two marking settings: with marking on the bytes frame the mark, so the row is a
    // document; with it off they frame nothing, and a document over them would state an empty item list,
    // which is the refusal this row is published for.
    expect([unmarked.expected, marked.expected]).toEqual(['BAD_PAYLOAD', 'verify-ok']);
    expect([unmarked.marking, marked.marking]).toEqual(['none', 'provenance-v1']);
    expect(frameResponse(unmarked.contentType!, unmarked.responseBytes).framed).toBe(false);
    const framed = frameResponse(marked.contentType!, marked.responseBytes);
    expect(framed.framed && framed.items).toHaveLength(1);
    // One response is the other with the marking frame written ahead of it, and that frame is the one
    // item the marked document attests, so the pair is one completion read under two settings.
    const [markLine, separator, terminator] = marked.assembledFrom!.map((piece) => publishedPiece(piece));
    expect(toHex(concatBytes([markLine!, separator!, terminator!]))).toBe(toHex(marked.responseBytes));
    expect(toHex(concatBytes([terminator!]))).toBe(toHex(unmarked.responseBytes));
    expect(marked.items).toHaveLength(1);
    // The one item these bytes frame is the marking frame with its field name taken off: `mk.d` digests
    // the line as transmitted and `itm[0].d` digests what the line says, so one frame is two spans and
    // this row states both.
    const prefix = encode(loadResVectors().framing.fieldPrefix);
    expect(bytesOf(marked.items![0]!.bytesBase64Url)).toEqual(markLine!.slice(prefix.length));
    const marked3 = decodeReceipt(marked.receipt).payload;
    expect(toHex(hashRequest(markLine!))).toBe(toHex(marked3.mk.d));
  });
});

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
