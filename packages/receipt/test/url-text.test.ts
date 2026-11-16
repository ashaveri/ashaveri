import { describe, expect, it } from 'vitest';
import { stripTrailingSlashes } from '../src/url-text.js';

describe('stripTrailingSlashes', () => {
  it('returns a string with no trailing slash unchanged', () => {
    expect(stripTrailingSlashes('https://api.example.com/v1')).toBe('https://api.example.com/v1');
  });

  it('removes one trailing slash', () => {
    expect(stripTrailingSlashes('https://api.example.com/')).toBe('https://api.example.com');
  });

  it('removes every trailing slash', () => {
    expect(stripTrailingSlashes('https://api.example.com///')).toBe('https://api.example.com');
  });

  it('preserves internal slashes, including internal runs', () => {
    expect(stripTrailingSlashes('https://api.example.com/v1/')).toBe('https://api.example.com/v1');
    expect(stripTrailingSlashes('https://api.example.com//v1//')).toBe('https://api.example.com//v1');
  });

  it('returns the empty string unchanged', () => {
    expect(stripTrailingSlashes('')).toBe('');
  });

  it('returns the empty string for an all-slash input', () => {
    expect(stripTrailingSlashes('////')).toBe('');
  });

  // A slash run ending in a non-slash has no trailing slash, so the correct
  // result is the input unchanged; it is also the shape an anchored
  // plus-quantified slash pattern backtracks over from every start position.
  // The scan visits each character once.
  it('leaves a 50,000-slash run followed by a non-slash unchanged', () => {
    const input = '/'.repeat(50_000) + 'x';
    expect(stripTrailingSlashes(input)).toBe(input);
  });

  it('strips a 50,000-slash run after a base URL', () => {
    expect(stripTrailingSlashes('https://api.example.com' + '/'.repeat(50_000))).toBe(
      'https://api.example.com',
    );
  });
});