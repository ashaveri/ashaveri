import { describe, expect, it } from 'vitest';
import {
  DUTY_LABEL_REGISTRY_REVISION,
  RETENTION_DUTY_LABELS,
  RETENTION_DUTY_REGISTRY,
  dutyLabelEntry,
} from '../src/index.js';

/**
 * Holds the published duty-label registry to the claims its own prose makes.
 *
 * The registry is the pack reader's question, not the retention layout's: the layout closes its
 * `duty.article` at the three labels its schema enumerates, while the pack container declares `art` a bare
 * text string and asks this registry which labels it can read. The two sets are therefore deliberately
 * different, and the relation a test can hold is that every label the layout enumerates is an entry here,
 * so a widening of the enum cannot leave a label the pack reader has never heard of. The registry grows
 * past the enum, and the growth entry is readable in a pack while the retention manifest still refuses it.
 *
 * The revision is one shared instant rather than one per label, because the labels are read from one
 * mapping. It is asserted against the calendar instant it names, not against a copy of itself, so a drift
 * between the constant and the prose that states the instant is a failure here.
 */

describe('the duty-label registry', () => {
  it('carries an entry for every label the retention layout enumerates', () => {
    for (const label of RETENTION_DUTY_LABELS) {
      const entry = dutyLabelEntry(label);
      expect(entry, `the layout enumerates ${label} but the registry has no entry for it`).toBeDefined();
      expect(entry?.article).toBe(label);
    }
  });

  it('names each label once', () => {
    const labels = RETENTION_DUTY_REGISTRY.map((entry) => entry.article);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it('grows past the enum with a label the retention layout does not carry', () => {
    const growth = RETENTION_DUTY_REGISTRY.filter(
      (entry) => !(RETENTION_DUTY_LABELS as readonly string[]).includes(entry.article),
    );
    expect(growth.length).toBeGreaterThan(0);
    expect(growth.map((entry) => entry.article)).toContain('5(1)(e)');
  });

  it('demands one shared mapping revision, the instant its prose names', () => {
    expect(DUTY_LABEL_REGISTRY_REVISION).toBe(Date.UTC(2026, 10, 16) / 1000);
    for (const entry of RETENTION_DUTY_REGISTRY) {
      expect(entry.mappingRevision).toBe(DUTY_LABEL_REGISTRY_REVISION);
    }
  });

  it('states an instrument, a jurisdiction, a period and a citation for every entry', () => {
    for (const entry of RETENTION_DUTY_REGISTRY) {
      expect(entry.instrument.length, `${entry.article} names no instrument`).toBeGreaterThan(0);
      expect(entry.jurisdiction.length, `${entry.article} names no jurisdiction`).toBeGreaterThan(0);
      expect(entry.period.length, `${entry.article} states no period`).toBeGreaterThan(0);
      expect(entry.citation, `${entry.article} cites no instrument version`).toContain('Regulation (EU)');
      expect(entry.citation, `${entry.article} cites no corpus file and line`).toMatch(/article-\d+\.txt:\d+/u);
    }
  });

  it('answers a known label with its entry and an unknown label with nothing', () => {
    expect(dutyLabelEntry('19(1)')?.instrument).toBe('ai-act');
    expect(dutyLabelEntry('5(1)(e)')?.instrument).toBe('gdpr');
    expect(dutyLabelEntry('12(1)')).toBeUndefined();
    expect(dutyLabelEntry('')).toBeUndefined();
  });
});