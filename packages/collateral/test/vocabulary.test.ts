import { describe, expect, it } from 'vitest';
import { collateralRefusal, collateralRefusals, quotable } from '../src/index.js';

describe('refusal vocabulary', () => {
  const entries = collateralRefusals();

  it('declares at least one refusal', () => {
    expect(entries.length).toBeGreaterThan(0);
  });

  it('names the layer in every code, which is what a bare string in a log has to do', () => {
    for (const entry of entries) {
      expect(entry.code, entry.code).toMatch(/^COLLATERAL_[A-Z0-9_]+$/u);
    }
  });

  it('states one sentence and one verdict per code', () => {
    const seen = new Set<string>();
    for (const entry of entries) {
      expect(entry.message.length, entry.code).toBeGreaterThan(0);
      expect(entry.message, entry.code).not.toContain('\n');
      expect(['terminal', 'retryable'], entry.code).toContain(entry.verdict);
      seen.add(entry.code);
    }
    expect(seen.size, 'codes are declared once each').toBe(entries.length);
  });

  it('keeps a refusal to the line it started on', () => {
    const built = collateralRefusal('COLLATERAL_BLOB_UNREADABLE', 'x'.repeat(400));
    expect(built.detail.split('\n')).toHaveLength(1);
    expect(built.detail.length).toBeLessThanOrEqual(300);
  });

  it('declines to quote a token that cannot be printed safely', () => {
    expect(quotable('OutOfDate:ConfigurationNeeded')).toBe(true);
    expect(quotable('two\nlines')).toBe(false);
    expect(quotable('')).toBe(false);
    expect(quotable('a'.repeat(65))).toBe(false);
  });
});
