import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DISCLOSURE_DUTY_CITATIONS,
  DISCLOSURE_DUTY_POINTERS,
  DISCLOSURE_RECORD_LIMITS,
  ReceiptError,
  encodeDisclosureRecord,
  extractMarkedRegion,
  fromBase64Url,
  parseDisclosureRecord,
  toHex,
} from '@ashaveri/receipt';
import { loadDisclosureRecordVectors, loadMarkingVectors } from '../src/index.js';

/**
 * The published disclosure record vectors, replayed the way a port replays them: read the record
 * bytes, hand them to the shipped reader, and answer the verdict the row promises. The accepted rows
 * are also written back through the shipped writer, so the bytes a port holds are the bytes this
 * repository's own writer produces for the record they parse to.
 *
 * The transformation outcomes are re-measured here rather than trusted: this file implements the four
 * transformations its own way, over the response bytes the family's rule block publishes, and holds
 * every accepted record's outcomes to what that run locates. The generator measures the same fact
 * through its own implementations, and two readings that share no code are the cross-check: a
 * generator that typed an outcome beside a transformation it never ran disagrees with this file.
 */

const file = loadDisclosureRecordVectors();

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** The completion's displayed text, read the way a render or a plain-text export reads it. */
function contentOf(bytes: Uint8Array): string {
  const body = JSON.parse(decoded(bytes)) as { choices: Array<{ message: { content: string } }> };
  return body.choices[0]!.message.content;
}

/** This file's own implementations, sharing nothing with the generator's beyond the names. */
const RUNS: Readonly<Record<string, (bytes: Uint8Array) => Uint8Array>> = {
  'byte-copy': (bytes) => Uint8Array.from(bytes),
  'json-reparse': (bytes) => encoded(JSON.stringify(JSON.parse(decoded(bytes)))),
  'text-render': (bytes) => encoded(contentOf(bytes)),
  'plain-text-export': (bytes) => encoded(contentOf(bytes) + '\n'),
};

function measuredOutcome(bytes: Uint8Array): 'detectable' | 'not-detectable' {
  try {
    extractMarkedRegion('provenance-v1', bytes);
    return 'detectable';
  } catch {
    return 'not-detectable';
  }
}

function verdictOf(bytes: Uint8Array): string {
  try {
    parseDisclosureRecord(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

describe('the disclosure record vectors', () => {
  it('publish the registries and the limits sentence the format owns', () => {
    expect(file.rule.dutyPointers).toEqual([...DISCLOSURE_DUTY_POINTERS]);
    expect(file.rule.dutyCitations).toEqual({ ...DISCLOSURE_DUTY_CITATIONS });
    expect(file.rule.limits).toBe(DISCLOSURE_RECORD_LIMITS);
    expect(file.rule.reader).toBe('parseDisclosureRecord in @ashaveri/receipt');
    expect(file.rule.writer).toBe('disclosureRecordBytes in @ashaveri/receipt');
  });

  it('answer as each row promises, and the accepted bytes are the writer\'s own', () => {
    for (const one of file.vectors) {
      const bytes = fromBase64Url(one.recordBase64Url);
      expect(bytes.length, `${one.name} byte length`).toBe(one.recordByteLength);
      expect(verdictOf(bytes), one.name).toBe(one.expected);
      if (one.expected === 'verify-ok') {
        expect(encodeDisclosureRecord(parseDisclosureRecord(bytes)), `${one.name} writer bytes`).toEqual(bytes);
      } else {
        expect(one.fault, `${one.name} states a refusal with no position`).toBeDefined();
      }
    }
    expect(file.vectors.some((one) => one.expected !== 'verify-ok')).toBe(true);
  });

  it('state outcomes this file\'s own harness run measures, over the published response', () => {
    const response = fromBase64Url(file.rule.contentPath.responseBase64Url);
    const implemented = file.rule.transformations.filter((one) => one.implemented).map((one) => one.name);
    const untested = file.rule.transformations.filter((one) => !one.implemented).map((one) => one.name);
    expect(implemented.sort()).toEqual(Object.keys(RUNS).sort());
    for (const one of file.vectors.filter((each) => each.expected === 'verify-ok')) {
      const record = parseDisclosureRecord(fromBase64Url(one.recordBase64Url));
      expect(record.transformations.map((each) => each.name).sort(), `${one.name} roster`).toEqual(
        [...implemented, ...untested].sort(),
      );
      for (const entry of record.transformations) {
        if (untested.includes(entry.name)) {
          expect(entry.outcome, `${one.name} ${entry.name}`).toBe('untested');
          continue;
        }
        const run = RUNS[entry.name];
        expect(run, `${one.name} names a transformation this harness does not implement`).toBeDefined();
        expect(entry.outcome, `${one.name} ${entry.name}`).toBe(measuredOutcome(run!(response)));
      }
    }
  });

  it('name the region by the digest the marking suite attests for the same bytes', () => {
    const marking = loadMarkingVectors().vectors.find((one) => one.name === 'buffered-member');
    expect(marking).toBeDefined();
    const response = fromBase64Url(file.rule.contentPath.responseBase64Url);
    expect(toHex(sha256(response))).toBe(toHex(sha256(fromBase64Url(marking!.responseBase64Url))));
    const region = extractMarkedRegion('provenance-v1', response);
    expect(toHex(sha256(region))).toBe(marking!.dHex);
    const record = parseDisclosureRecord(
      fromBase64Url(file.vectors.find((one) => one.name === 'record-marked-region-v1')!.recordBase64Url),
    );
    expect(record.served.kind).toBe('region');
    if (record.served.kind === 'region') expect(record.served.sha256).toBe(marking!.dHex);
  });

  it('state the fixture path as the fixture it is, and name where the real path is recorded', () => {
    expect(file.rule.contentPath.response).toBe('marking-v1.json#buffered-member');
    expect(file.description).toContain('No row carries a claim');
    expect(file.rule.contentPath.note).toContain('rule.realContentPath');
    for (const one of file.rule.transformations.filter((each) => !each.implemented)) {
      expect(one.note).toContain('untested');
    }
  });
});

/**
 * The same completion put through the copying, rendering and export transformations of applications
 * that exist outside this repository, each stage published with the bytes those applications produced
 * so the verdict beside it is this file's own reading of them rather than a word beside a name.
 *
 * The fixture harness above can only say what the rule locates after a transformation this package
 * implements. These rows are a recorded run of real applications over the same starting bytes, and the
 * split they measure is the one the limits sentence draws: a copy of the transcript still carries the
 * region, and a rendered document of it carries none.
 */
describe('the real content path measured beside the fixture harness', () => {
  const real = file.rule.realContentPath;

  it('starts from the response the marking suite publishes', () => {
    expect(real).toBeDefined();
    const start = fromBase64Url(real.startBase64Url);
    expect(toHex(sha256(start))).toBe(toHex(sha256(fromBase64Url(file.rule.contentPath.responseBase64Url))));
    expect(real.start).toBe('marking-v1.json#buffered-member');
  });

  it('publishes for each measured stage the bytes the application produced', () => {
    for (const stage of real.stages.filter((one) => one.outcome !== 'untested')) {
      expect(stage.outputBase64Url, `${stage.name} states a verdict over no bytes`).toBeDefined();
      expect(stage.application, `${stage.name} states a verdict produced by no application`).not.toBe('');
      expect(stage.applicationVersion, `${stage.name} states a verdict from an unversioned application`).not.toBe('');
    }
  });

  it('states outcomes this file\'s own reading of the published stage bytes gives', () => {
    for (const stage of real.stages) {
      if (stage.outputBase64Url === undefined) {
        expect(stage.outcome, `${stage.name} publishes no bytes and states a verdict`).toBe('untested');
        continue;
      }
      expect(stage.outcome, stage.name).toBe(measuredOutcome(fromBase64Url(stage.outputBase64Url)));
    }
  });

  it('carries the copy through and loses the mark at every rendering, export and scan stage', () => {
    const byName = new Map(real.stages.map((one) => [one.name, one.outcome]));
    expect(byName.get('client-fetch-to-file')).toBe('detectable');
    for (const name of ['browser-rendered-document', 'browser-exported-pdf', 'pdf-text-export', 'pdf-text-export-second-application', 'pdf-page-raster-ocr-text']) {
      expect(byName.get(name), name).toBe('not-detectable');
    }
  });

  it('records a stage it could not run, and words its reason as a stage rather than a verdict', () => {
    const unrun = real.stages.filter((one) => one.outcome === 'untested');
    expect(unrun.length, 'no stage of the intended path went unrun').toBeGreaterThan(0);
    for (const one of unrun) {
      expect(one.note, `${one.name} records no reason for its silence`).not.toBe('');
      expect(one.outputBase64Url, `${one.name} published bytes beside an untested outcome`).toBeUndefined();
    }
    const words = unrun.map((one) => one.name).sort();
    expect(words).toEqual(['media-container-transcode', 'office-document-export']);
  });
});